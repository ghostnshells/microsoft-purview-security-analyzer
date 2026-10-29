"""Shared presentation helpers for audit tables and bounded map tooltips."""
from html import escape
import math

import folium
from folium.plugins import MarkerCluster
import pandas as pd


def event_table(events):
    """Return Arrow-friendly values without expensive per-cell HTML styling."""
    frame = pd.DataFrame(events)
    if 'Timestamp' in frame:
        frame['Timestamp'] = pd.to_datetime(
            frame['Timestamp'], errors='coerce', utc=True, format='mixed'
        ).dt.strftime('%Y-%m-%d %H:%M:%S UTC').fillna('Unknown')
    for col in frame.columns:
        if not (pd.api.types.is_object_dtype(frame[col]) or isinstance(frame[col].dtype, pd.StringDtype)):
            continue
        frame[col] = frame[col].map(
            lambda value: ', '.join(map(str, value)) if isinstance(value, (list, tuple))
            else str(value) if value is not None else ''
        )
    priority = ['Timestamp', 'RiskLevel', 'Operation', 'ClientIP', 'City', 'Region', 'Country', 'UserId', 'AnomalyTypes']
    return frame[[c for c in priority if c in frame] + [c for c in frame if c not in priority]]


def group_locations(events):
    groups = {}
    for event in events:
        try:
            lat, lon = float(event['Latitude']), float(event['Longitude'])
        except (KeyError, TypeError, ValueError):
            continue
        if not (math.isfinite(lat) and math.isfinite(lon) and -90 <= lat <= 90 and -180 <= lon <= 180):
            continue
        if (lat, lon) == (0, 0) or event.get('Country') in ('Unknown', 'Local'):
            continue
        groups.setdefault((lat, lon), []).append(event)
    return groups


def create_activity_map(groups):
    m = folium.Map(location=[20, 0], zoom_start=2, control_scale=True, prefer_canvas=True)
    cluster = MarkerCluster().add_to(m)
    for coordinates, events in groups.items():
        # Only a single summary is embedded per marker, regardless of event volume.
        dates = pd.to_datetime([e.get('Timestamp') for e in events], errors='coerce', utc=True, format='mixed')
        latest_index = max(range(len(events)), key=lambda i: dates[i].value)
        event = events[latest_index]
        location = ', '.join(str(event.get(k) or 'Unknown')[:60] for k in ['City', 'Region', 'Country'])
        stamp = dates[latest_index].strftime('%Y-%m-%d %H:%M UTC') if pd.notna(dates[latest_index]) else 'Unknown time'
        tooltip = '<br>'.join([
            f'<b>{escape(location)}</b>', f'{len(events):,} events',
            f'Latest: {escape(stamp)}', escape(str(event.get('Operation', 'Unknown action'))[:100]),
            'Click pin to view events below the map',
        ])
        folium.Marker(coordinates, tooltip=folium.Tooltip(tooltip, sticky=False, direction='top'),
                      icon=folium.Icon(color='red', icon='info-sign')).add_to(cluster)
    if groups:
        m.fit_bounds(list(groups), max_zoom=10, padding=(40, 40))
    return m
