// Browser front end for the Microsoft Purview Security Analyzer.
//
// The analysis runs in the Python API (backend/server.py). This page reads the
// upload, trims CSV exports to the fields the analysis uses so they fit
// Vercel's 4.5 MB request limit, and applies the sidebar filters locally, the
// same way apply_filters() in security_analyzer.py does.

(function () {
  'use strict';

  // Vercel rejects request bodies over 4.5 MB; leave headroom for headers
  const MAX_UPLOAD_BYTES = 4.4 * 1024 * 1024;
  const PAGE_SIZE = 100;
  // AuditData fields that build_timeline() reads
  const AUDIT_FIELDS = ['ClientIP', 'ResultStatus', 'SourceFileName'];
  const REQUIRED_COLUMNS = ['CreationDate', 'Operation', 'UserId', 'AuditData'];
  const ALL_RISK_LEVELS = ['High', 'Medium', 'Low'];
  // Events listed in one map popup; large exports can put thousands at one spot
  const MAX_POPUP_EVENTS = 50;

  const $ = (id) => document.getElementById(id);

  const state = {
    events: null,        // every event, enriched by the API
    compromised: [],
    filesAccessed: [],
    anomalous: [],
    map: null,
    markerLayer: null,
    tables: {},
  };

  // ---------- Upload and analysis ----------

  function showStatus(text, percent) {
    $('status').hidden = false;
    $('status-text').textContent = text;
    $('progress-bar').style.width = percent + '%';
  }

  function hideStatus() {
    $('status').hidden = true;
  }

  function showMessage(text, kind) {
    const el = $('message');
    el.className = 'message ' + kind;
    el.textContent = text;
    el.hidden = false;
  }

  function clearMessage() {
    $('message').hidden = true;
  }

  function parseCsv(file) {
    return new Promise((resolve, reject) => {
      Papa.parse(file, {
        header: true,
        skipEmptyLines: 'greedy',
        complete: resolve,
        error: reject,
      });
    });
  }

  // Keep only the AuditData fields the analysis reads. Values that are not a
  // JSON object pass through unchanged, so the API skips them as before.
  function trimAuditData(value) {
    if (typeof value !== 'string') return value;
    let parsed;
    try {
      parsed = JSON.parse(value);
    } catch (e) {
      return value;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return value;
    const trimmed = {};
    for (const key of AUDIT_FIELDS) {
      if (key in parsed) trimmed[key] = parsed[key];
    }
    return JSON.stringify(trimmed);
  }

  async function gzip(text) {
    if (typeof CompressionStream === 'undefined') return null;
    const stream = new Blob([text]).stream().pipeThrough(new CompressionStream('gzip'));
    return new Blob([await new Response(stream).arrayBuffer()]);
  }

  async function buildCsvUpload(file) {
    const parsed = await parseCsv(file);
    const fields = parsed.meta.fields || [];
    const missing = REQUIRED_COLUMNS.find((col) => !fields.includes(col));
    if (missing) {
      throw new Error(`Required column '${missing}' not found in the input file`);
    }
    const records = parsed.data.map((row) => ({
      CreationDate: row.CreationDate,
      Operation: row.Operation,
      UserId: row.UserId,
      AuditData: trimAuditData(row.AuditData),
    }));
    const json = JSON.stringify(records);
    const compressed = await gzip(json);
    if (compressed) {
      return { body: compressed, format: 'records', encoding: 'gzip' };
    }
    return { body: new Blob([json], { type: 'application/json' }), format: 'records', encoding: '' };
  }

  async function analyzeFile(file) {
    clearMessage();
    $('results').hidden = true;
    $('empty-state').hidden = true;

    const extension = file.name.split('.').pop().toLowerCase();
    if (!['csv', 'xlsx', 'xls'].includes(extension)) {
      throw new Error('Unsupported file format. Upload a CSV or Excel file.');
    }

    showStatus('Reading and parsing the file...', 10);
    const upload = extension === 'csv'
      ? await buildCsvUpload(file)
      : { body: file, format: extension, encoding: '' };

    if (upload.body.size > MAX_UPLOAD_BYTES) {
      throw new Error(extension === 'csv'
        ? 'This export is too large for the hosted analyzer, even after trimming it to the fields the analysis uses. Split the export into smaller date ranges, or run the analyzer locally.'
        : 'Excel uploads are limited to about 4.4 MB on the hosted analyzer. Export the audit log as CSV instead, which is trimmed in your browser before upload, or run the analyzer locally.');
    }

    showStatus('Processing IP geolocation data...', 50);
    const headers = { 'X-Upload-Format': upload.format };
    if (upload.encoding) headers['X-Upload-Encoding'] = upload.encoding;
    const response = await fetch('/api/analyze', { method: 'POST', headers, body: upload.body });

    showStatus('Analyzing anomalies and generating insights...', 80);
    let payload;
    try {
      payload = await response.json();
    } catch (e) {
      payload = null;
    }
    if (!response.ok) {
      if (response.status === 413) {
        throw new Error('The upload is too large for the hosted analyzer. Split the export into smaller date ranges, or run the analyzer locally.');
      }
      throw new Error((payload && payload.detail) || `The analyzer returned an error (${response.status}).`);
    }
    return payload;
  }

  function loadResult(result) {
    const events = result.rows.map((row, i) => {
      const event = {};
      result.columns.forEach((col, c) => { event[col] = row[c]; });
      // Fields used only for filtering, never shown
      Object.defineProperty(event, '_hour', { value: result.hour[i] });
      Object.defineProperty(event, '_weekday', { value: result.weekday[i] });
      Object.defineProperty(event, '_clock', { value: result.clock[i] });
      return event;
    });
    state.events = events;
    state.compromised = result.compromised.map((i) => events[i]);
    state.filesAccessed = result.filesAccessed.map((i) => events[i]);
    state.anomalous = result.anomalous.map((i) => events[i]);
  }

  async function handleFile(file) {
    if (!file) return;
    $('file-name').textContent = file.name;
    try {
      const result = await analyzeFile(file);
      loadResult(result);
      showStatus('', 100);
      hideStatus();
      let note = `Successfully processed ${state.events.length} events.`;
      if (!result.geoip) note += '\nThe GeoLite2 database could not be loaded, so IP geolocation is limited.';
      showMessage(note, 'success');
      $('results').hidden = false;
      render();
    } catch (e) {
      hideStatus();
      $('empty-state').hidden = false;
      showMessage(`An error occurred during processing: ${e.message}`, 'error');
    }
  }

  // ---------- Filters (port of apply_filters in security_analyzer.py) ----------

  function checkedValues(containerId) {
    return Array.from($(containerId).querySelectorAll('input:checked')).map((el) => el.value);
  }

  function readFilters() {
    const timeEnabled = $('time-enabled').checked;
    const ipEnabled = $('ip-enabled').checked;
    const timeType = $('time-type').value;
    const normalizeTime = (value) => (value && value.length === 5 ? value + ':00' : value);
    return {
      riskLevels: checkedValues('risk-levels'),
      anomalyTypes: checkedValues('anomaly-types'),
      excludedCountries: $('geo-enabled').checked ? checkedValues('excluded-countries') : [],
      timeEnabled,
      timeFilterType: timeEnabled ? timeType : null,
      startTime: normalizeTime($('start-time').value),
      endTime: normalizeTime($('end-time').value),
      ipEnabled,
      ipFilterOptions: ipEnabled ? checkedValues('ip-patterns') : [],
    };
  }

  function applyTimeFilter(events, config) {
    const type = config.timeFilterType;
    return events.filter((e) => {
      const hour = e._hour;
      const weekday = e._weekday;
      if (hour == null || weekday == null) return true;
      switch (type) {
        case 'Business Hours Only':
          return hour >= 8 && hour <= 17 && weekday < 5;
        case 'Outside Business Hours':
          return hour < 8 || hour > 17 || weekday >= 5;
        case 'Weekends Only':
          return weekday >= 5;
        case 'Custom Range':
          // Until both times are set, the range does not filter anything
          if (!config.startTime || !config.endTime) return true;
          return config.startTime <= e._clock && e._clock <= config.endTime;
        default:
          return true;
      }
    });
  }

  function applyIpPatternFilter(events, options) {
    const ipCounts = new Map();
    const ipCountries = new Map();
    for (const e of events) {
      const ip = e.ClientIP == null ? 'N/A' : e.ClientIP;
      ipCounts.set(ip, (ipCounts.get(ip) || 0) + 1);
      if (!ipCountries.has(ip)) ipCountries.set(ip, new Set());
      ipCountries.get(ip).add(e.Country == null ? 'Unknown' : e.Country);
    }
    return events.filter((e) => {
      const ip = e.ClientIP == null ? 'N/A' : e.ClientIP;
      return options.some((option) => {
        if (option === 'First-time IPs' || option === 'Single-use IPs') return ipCounts.get(ip) === 1;
        if (option === 'Frequent IPs') return ipCounts.get(ip) > 10;
        if (option === 'Cross-country IPs') return ipCountries.get(ip).size > 1;
        return false;
      });
    });
  }

  function applyFilters(events, config) {
    let filtered = events;
    if (config.riskLevels.length) {
      filtered = filtered.filter((e) => config.riskLevels.includes(e.RiskLevel));
    }
    if (config.anomalyTypes.length) {
      filtered = filtered.filter((e) => e.AnomalyTypes.some((t) => config.anomalyTypes.includes(t)));
    }
    if (config.excludedCountries.length) {
      filtered = filtered.filter((e) => !config.excludedCountries.includes(e.Country == null ? 'Unknown' : e.Country));
    }
    if (config.timeFilterType) {
      filtered = applyTimeFilter(filtered, config);
    }
    if (config.ipFilterOptions.length) {
      filtered = applyIpPatternFilter(filtered, config.ipFilterOptions);
    }
    return filtered;
  }

  function activeFilterSummary(config) {
    const active = [];
    if (config.riskLevels.length && config.riskLevels.length < 3) active.push(`Risk: ${config.riskLevels.join(', ')}`);
    if (config.anomalyTypes.length) active.push(`Types: ${config.anomalyTypes.join(', ')}`);
    if (config.excludedCountries.length) active.push(`Excluded: ${config.excludedCountries.join(', ')}`);
    if (config.timeEnabled) active.push(`Time: ${config.timeFilterType}`);
    if (config.ipEnabled && config.ipFilterOptions.length) active.push(`IP: ${config.ipFilterOptions.join(', ')}`);
    return active;
  }

  // ---------- Rendering ----------

  function escapeHtml(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function displayValue(value) {
    if (value == null) return '';
    if (Array.isArray(value)) return value.join(', ');
    return String(value);
  }

  function ensureMap() {
    if (state.map) return;
    state.map = L.map('map').setView([20, 0], 2);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 18,
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
    }).addTo(state.map);
    state.markerLayer = L.layerGroup().addTo(state.map);
  }

  function renderMap(anomalous) {
    const hasEvents = anomalous.length > 0;
    $('map').hidden = !hasEvents;
    $('map-empty').hidden = hasEvents;
    $('anomalous-section').hidden = !hasEvents;
    if (!hasEvents) return;

    ensureMap();
    state.markerLayer.clearLayers();

    const locations = new Map();
    for (const e of anomalous) {
      if (e.Country === 'Unknown' || e.Region === 'Unknown') continue;
      const lat = e.Latitude || 0;
      const lon = e.Longitude || 0;
      if (lat === 0 && lon === 0) continue;
      const key = `${lat}_${lon}`;
      if (!locations.has(key)) locations.set(key, { lat, lon, events: [] });
      locations.get(key).events.push(e);
    }

    for (const loc of locations.values()) {
      let html = '<div><h4>Location Events</h4>';
      loc.events.slice(0, MAX_POPUP_EVENTS).forEach((e, i) => {
        html += '<div class="popup-event">'
          + `<p><b>Event ${i + 1}</b></p>`
          + `<p><b>IP Address:</b> ${escapeHtml(e.ClientIP)}</p>`
          + `<p><b>Timestamp:</b> ${escapeHtml(e.Timestamp)}</p>`
          + `<p><b>Operation:</b> ${escapeHtml(e.Operation)}</p>`
          + `<p><b>User ID:</b> ${escapeHtml(e.UserId)}</p>`
          + `<p><b>Location:</b> ${escapeHtml(e.Region)}, ${escapeHtml(e.Country)}</p>`
          + '</div>';
      });
      if (loc.events.length > MAX_POPUP_EVENTS) {
        html += `<p><i>...and ${loc.events.length - MAX_POPUP_EVENTS} more events</i></p>`;
      }
      html += '</div>';
      L.circleMarker([loc.lat, loc.lon], {
        radius: 9, color: '#b30000', weight: 2, fillColor: '#ff4444', fillOpacity: 0.85,
      })
        .bindPopup(html, { maxWidth: 350 })
        .bindTooltip(`${loc.events.length} event(s) at this location`)
        .addTo(state.markerLayer);
    }
    // The map may have been laid out while its tab was hidden
    setTimeout(() => state.map.invalidateSize(), 0);
  }

  // A sortable, searchable, paged table
  function createTable(containerId, emptyText) {
    const container = $(containerId);
    const table = { rows: [], columns: [], sortCol: null, sortDir: 1, page: 0, query: '' };

    const tools = document.createElement('div');
    tools.className = 'table-tools';
    const search = document.createElement('input');
    search.type = 'search';
    search.placeholder = 'Search';
    const count = document.createElement('span');
    count.className = 'muted';
    tools.append(search, count);

    const wrap = document.createElement('div');
    wrap.className = 'table-wrap';
    const tableEl = document.createElement('table');
    wrap.append(tableEl);

    const pager = document.createElement('div');
    pager.className = 'pager table-tools';
    const prev = document.createElement('button');
    prev.className = 'button secondary';
    prev.textContent = 'Previous';
    const pageLabel = document.createElement('span');
    pageLabel.className = 'muted';
    const next = document.createElement('button');
    next.className = 'button secondary';
    next.textContent = 'Next';
    pager.append(prev, pageLabel, next);

    const empty = document.createElement('div');
    empty.className = 'message info';
    empty.textContent = emptyText;

    container.append(tools, wrap, pager, empty);

    function visibleRows() {
      let rows = table.rows;
      if (table.query) {
        const q = table.query.toLowerCase();
        rows = rows.filter((r) => table.columns.some((c) => displayValue(r[c]).toLowerCase().includes(q)));
      }
      if (table.sortCol) {
        const col = table.sortCol;
        rows = rows.slice().sort((a, b) => {
          const x = a[col];
          const y = b[col];
          if (x == null && y == null) return 0;
          if (x == null) return 1;
          if (y == null) return -1;
          if (typeof x === 'number' && typeof y === 'number') return (x - y) * table.sortDir;
          return displayValue(x).localeCompare(displayValue(y)) * table.sortDir;
        });
      }
      return rows;
    }

    function draw() {
      const hasRows = table.rows.length > 0;
      tools.hidden = wrap.hidden = pager.hidden = !hasRows;
      empty.hidden = hasRows;
      if (!hasRows) return;

      const rows = visibleRows();
      const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
      table.page = Math.min(table.page, pages - 1);
      const start = table.page * PAGE_SIZE;
      const pageRows = rows.slice(start, start + PAGE_SIZE);

      tableEl.replaceChildren();
      const thead = tableEl.createTHead().insertRow();
      for (const col of table.columns) {
        const th = document.createElement('th');
        th.textContent = col;
        if (col === table.sortCol) th.className = table.sortDir === 1 ? 'sorted-asc' : 'sorted-desc';
        th.addEventListener('click', () => {
          if (table.sortCol === col) table.sortDir = -table.sortDir;
          else { table.sortCol = col; table.sortDir = 1; }
          draw();
        });
        thead.append(th);
      }
      const tbody = tableEl.createTBody();
      for (const row of pageRows) {
        const tr = tbody.insertRow();
        for (const col of table.columns) {
          const td = tr.insertCell();
          td.textContent = displayValue(row[col]);
          if (col === 'RiskLevel' && ALL_RISK_LEVELS.includes(row[col])) td.className = `risk risk-${row[col]}`;
        }
      }

      count.textContent = `${rows.length} of ${table.rows.length} rows`;
      pageLabel.textContent = `Page ${table.page + 1} of ${pages}`;
      prev.disabled = table.page === 0;
      next.disabled = table.page >= pages - 1;
    }

    search.addEventListener('input', () => { table.query = search.value; table.page = 0; draw(); });
    prev.addEventListener('click', () => { table.page -= 1; draw(); });
    next.addEventListener('click', () => { table.page += 1; draw(); });

    return {
      setRows(rows, columns) {
        table.rows = rows;
        table.columns = columns;
        table.page = 0;
        draw();
      },
    };
  }

  let lastFiltered = null;

  function render() {
    if (!state.events) return;
    const config = readFilters();
    const filtered = {
      compromised: applyFilters(state.compromised, config),
      filesAccessed: applyFilters(state.filesAccessed, config),
      anomalous: applyFilters(state.anomalous, config),
      timeline: applyFilters(state.events, config),
    };
    lastFiltered = filtered;

    const active = activeFilterSummary(config);
    $('active-filters').hidden = active.length === 0;
    $('active-filters').textContent = `🔍 Active Filters: ${active.join(' | ')}`;

    const total = state.events.length;
    $('m-total').textContent = filtered.timeline.length;
    const delta = filtered.timeline.length - total;
    $('m-total-delta').textContent = active.length ? (delta > 0 ? '+' : '') + delta : '';
    $('m-suspicious').textContent = filtered.compromised.length;
    $('m-files').textContent = filtered.filesAccessed.length;
    $('m-anomalous').textContent = filtered.anomalous.length;

    const columns = Object.keys(state.events[0] || {});
    state.tables.anomalous.setRows(filtered.anomalous, columns);
    state.tables.suspicious.setRows(filtered.compromised, columns);
    state.tables.files.setRows(filtered.filesAccessed, columns);
    state.tables.all.setRows(filtered.timeline, columns);
    renderMap(filtered.anomalous);
  }

  function downloadResults() {
    if (!state.events || !lastFiltered) return;
    const output = {
      timeline: state.events,
      compromised_events: lastFiltered.compromised,
      files_accessed: lastFiltered.filesAccessed,
      anomalous_ips: lastFiltered.anomalous,
    };
    const blob = new Blob([JSON.stringify(output)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'security_analysis_results.json';
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  // ---------- Wiring ----------

  function bindToggle(checkboxId, sectionId) {
    $(checkboxId).addEventListener('change', () => {
      $(sectionId).hidden = !$(checkboxId).checked;
      render();
    });
  }

  function resetFilters() {
    document.querySelectorAll('#risk-levels input').forEach((el) => { el.checked = true; });
    document.querySelectorAll('#anomaly-types input, #ip-patterns input').forEach((el) => { el.checked = false; });
    document.querySelectorAll('#excluded-countries input').forEach((el) => { el.checked = el.value === 'Local'; });
    for (const [checkbox, section] of [['geo-enabled', 'geo-options'], ['time-enabled', 'time-options'], ['ip-enabled', 'ip-options']]) {
      $(checkbox).checked = false;
      $(section).hidden = true;
    }
    $('time-type').selectedIndex = 0;
    $('custom-range').hidden = true;
    $('start-time').value = '';
    $('end-time').value = '';
    render();
  }

  function selectTab(name) {
    document.querySelectorAll('.tab').forEach((tab) => {
      tab.classList.toggle('active', tab.dataset.tab === name);
    });
    document.querySelectorAll('.tab-panel').forEach((panel) => {
      panel.hidden = panel.id !== `panel-${name}`;
    });
    if (name === 'map' && state.map) setTimeout(() => state.map.invalidateSize(), 0);
  }

  function init() {
    state.tables.anomalous = createTable('table-anomalous', 'No anomalous IP activity detected in the data.');
    state.tables.suspicious = createTable('table-suspicious', 'No suspicious events detected in the data.');
    state.tables.files = createTable('table-files', 'No file access events found in the data.');
    state.tables.all = createTable('table-all', 'No events match the current filters.');

    const input = $('file-input');
    input.addEventListener('change', () => handleFile(input.files[0]));

    const dropZone = document.querySelector('.upload');
    dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('dragging'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragging'));
    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.classList.remove('dragging');
      handleFile(e.dataTransfer.files[0]);
    });

    document.querySelectorAll('#sidebar .checks input').forEach((el) => {
      el.addEventListener('change', render);
    });
    bindToggle('geo-enabled', 'geo-options');
    bindToggle('time-enabled', 'time-options');
    bindToggle('ip-enabled', 'ip-options');
    $('time-type').addEventListener('change', () => {
      $('custom-range').hidden = $('time-type').value !== 'Custom Range';
      render();
    });
    $('start-time').addEventListener('change', render);
    $('end-time').addEventListener('change', render);
    $('reset-filters').addEventListener('click', resetFilters);
    $('download').addEventListener('click', downloadResults);

    document.querySelectorAll('.tab').forEach((tab) => {
      tab.addEventListener('click', () => selectTab(tab.dataset.tab));
    });
  }

  init();
})();
