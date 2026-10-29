"""
FastAPI backend for the Microsoft Purview Security Analyzer.

Vercel runs this module as a single Python function (see [tool.vercel] in
pyproject.toml). The browser front end lives in public/ and is served from
Vercel's CDN. The analysis itself is the same code the Streamlit app uses,
in security_analyzer.py.

Vercel limits shape the API:
- Request and response bodies are capped at 4.5 MB, so the browser trims CSV
  exports down to the fields the analysis reads and gzips them before upload,
  and the response is sent column-wise and gzip-compressed.
- Functions are stateless, so filtering happens in the browser on the
  enriched events this endpoint returns.
"""

import json
import math
import os
import tempfile
import zlib

import pandas as pd
from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

from security_analyzer import (
    DEFAULT_GEOIP_DB_PATH,
    assign_risk_level,
    build_timeline,
    classify_anomaly_type,
    detect_compromised_events,
    filter_anomalous_ips,
    filter_files_accessed,
    load_audit_dataframe,
    open_geo_reader,
)

# Largest upload we will decompress, to guard against gzip bombs
MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024

UPLOAD_FORMATS = {"records", "csv", "xlsx", "xls"}

# Order of the columns sent to the browser
EVENT_COLUMNS = [
    'Timestamp', 'RiskLevel', 'AnomalyTypes', 'Operation', 'UserId', 'ClientIP',
    'ResultStatus', 'FileName', 'Country', 'Region', 'City', 'Latitude', 'Longitude',
]

app = FastAPI(title="Microsoft Purview Security Analyzer API")
app.add_middleware(GZipMiddleware, minimum_size=1000)

# The GeoLite2 reader is opened once per warm function instance and reused
_geo_reader = None
_geo_reader_loaded = False


def get_geo_reader():
    global _geo_reader, _geo_reader_loaded
    if not _geo_reader_loaded:
        _geo_reader = open_geo_reader(DEFAULT_GEOIP_DB_PATH)
        _geo_reader_loaded = True
    return _geo_reader


def gunzip_limited(data):
    """Decompress gzip data, refusing anything that expands past the limit."""
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = decompressor.decompress(data, MAX_DECOMPRESSED_BYTES + 1)
    except zlib.error:
        raise HTTPException(status_code=400, detail="The upload is not valid gzip data.")
    if len(out) > MAX_DECOMPRESSED_BYTES or decompressor.unconsumed_tail:
        raise HTTPException(status_code=413, detail="The upload is too large to analyze.")
    return out


def load_upload(body, upload_format):
    """Build the audit log DataFrame from the uploaded bytes."""
    if upload_format == "records":
        try:
            records = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise HTTPException(status_code=400, detail="The upload is not valid JSON.")
        if not isinstance(records, list):
            raise HTTPException(status_code=400, detail="Expected a JSON array of audit log rows.")
        if not records:
            raise HTTPException(status_code=422, detail="The file has no audit log rows.")
        return pd.DataFrame(records)

    # Spreadsheets and raw CSV go through the same reader the Streamlit app uses.
    # /tmp is the only writable path on Vercel, and it is cleared between requests.
    with tempfile.NamedTemporaryFile(delete=False, suffix=f".{upload_format}") as tmp:
        tmp.write(body)
        temp_path = tmp.name
    try:
        return load_audit_dataframe(temp_path)
    finally:
        os.unlink(temp_path)


def json_safe(value):
    """Make pandas and numpy values JSON serializable."""
    if value is None or value is pd.NaT:
        return None
    if isinstance(value, pd.Timestamp):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    if isinstance(value, float) and math.isnan(value):
        return None
    if hasattr(value, 'item'):  # numpy scalars
        value = value.item()
        if isinstance(value, float) and math.isnan(value):
            return None
    return value


def analyze_timeline(timeline):
    """
    Run the analysis and pack the result column-wise for the browser.

    Every event is enriched once with RiskLevel and AnomalyTypes (what
    apply_filters adds in the Streamlit app), plus the hour, weekday and
    clock time the browser needs for the time filters.
    """
    compromised_events = detect_compromised_events(timeline)
    files_accessed = filter_files_accessed(timeline)
    anomalous_ips = filter_anomalous_ips(timeline)

    # The helpers return the same event objects, so map them back to positions
    index_of = {id(event): i for i, event in enumerate(timeline)}

    rows, hours, weekdays, clocks = [], [], [], []
    for event in timeline:
        enriched = dict(event)
        enriched['RiskLevel'] = assign_risk_level(enriched)
        enriched['AnomalyTypes'] = classify_anomaly_type(enriched)
        rows.append([json_safe(enriched.get(col)) for col in EVENT_COLUMNS])

        timestamp = pd.to_datetime(event.get('Timestamp'))
        hours.append(int(timestamp.hour) if pd.notna(timestamp) else None)
        weekdays.append(int(timestamp.weekday()) if pd.notna(timestamp) else None)
        clocks.append(timestamp.strftime('%H:%M:%S') if pd.notna(timestamp) else None)

    return {
        "columns": EVENT_COLUMNS,
        "rows": rows,
        "hour": hours,
        "weekday": weekdays,
        "clock": clocks,
        "compromised": [index_of[id(e)] for e in compromised_events],
        "filesAccessed": [index_of[id(e)] for e in files_accessed],
        "anomalous": [index_of[id(e)] for e in anomalous_ips],
    }


@app.get("/api/health")
def health():
    return {"status": "ok", "geoip": get_geo_reader() is not None}


@app.post("/api/analyze")
async def analyze(request: Request):
    upload_format = request.headers.get("x-upload-format", "").lower()
    if upload_format not in UPLOAD_FORMATS:
        raise HTTPException(status_code=400, detail="Unsupported file format. Upload a CSV or Excel file.")

    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="The upload is empty.")
    if request.headers.get("x-upload-encoding", "").lower() == "gzip":
        body = gunzip_limited(body)

    try:
        # Parsing and analysis are CPU-bound, so keep them off the event loop
        df = await run_in_threadpool(load_upload, body, upload_format)
        timeline = await run_in_threadpool(build_timeline, df, get_geo_reader())
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        print(f"Error processing upload: {e}")
        raise HTTPException(status_code=422, detail=f"Error processing file: {e}")

    if not timeline:
        raise HTTPException(
            status_code=422,
            detail="No data could be processed from the file. Please check the file format.",
        )

    result = await run_in_threadpool(analyze_timeline, timeline)
    result["geoip"] = get_geo_reader() is not None
    return JSONResponse(result)
