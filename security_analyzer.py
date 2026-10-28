import pandas as pd
import json
import os
import time
import ipaddress
import geoip2.database
from datetime import datetime, time as dt_time
from collections import Counter

# Pre-defined IP location data for known IPs (like Frans' usual IP)
KNOWN_IPS = {
    '192.168.1.160': {
        'Country': 'US',
        'Region': 'Massachusetts',
        'City': 'Boston',
        'Latitude': 42.3601,
        'Longitude': -71.0589
    }
}

def is_private_ip(ip):
    """Check if an IP address is private."""
    if ip == 'N/A':
        return True
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # If not a valid IP, treat as private

def get_ip_geolocation(ip, geo_reader=None):
    """
    Get geolocation data for an IP address using GeoLite2 database.
    
    Parameters:
    ip (str): IP address
    geo_reader: GeoLite2 database reader object
    
    Returns:
    dict: Geolocation data (country, region, city, latitude, longitude)
    """
    # Check for known IPs first (like Frans's usual IP)
    if ip in KNOWN_IPS:
        return KNOWN_IPS[ip]
    
    # Skip private IPs
    if is_private_ip(ip):
        return {
            'Country': 'Local',
            'Region': 'Network',
            'City': 'Private',
            'Latitude': 0,
            'Longitude': 0
        }
    
    # Try to use the GeoLite2 database
    if geo_reader and ip != 'N/A':
        try:
            response = geo_reader.city(ip)
            country = response.country.iso_code if response.country.iso_code else "Unknown"
            region = response.subdivisions.most_specific.name if response.subdivisions.most_specific.name else "Unknown"
            city = response.city.name if response.city.name else "Unknown"
            latitude = response.location.latitude if response.location.latitude else 0
            longitude = response.location.longitude if response.location.longitude else 0
            
            return {
                'Country': country,
                'Region': region,
                'City': city,
                'Latitude': latitude,
                'Longitude': longitude
            }
        except Exception as e:
            print(f"Error looking up IP {ip} in GeoLite2 database: {e}")
    
    # Default values if all lookups fail
    return {
        'Country': 'Unknown',
        'Region': 'Unknown',
        'City': 'Unknown',
        'Latitude': 0,
        'Longitude': 0
    }

# Default GeoLite2 location, resolved next to this module so it works no matter
# what the working directory is (Vercel runs functions from the bundle root).
DEFAULT_GEOIP_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attached_assets", "GeoLite2-City.mmdb")

REQUIRED_COLUMNS = ['CreationDate', 'Operation', 'UserId', 'AuditData']

def open_geo_reader(geoip_db_path=DEFAULT_GEOIP_DB_PATH):
    """
    Open the GeoLite2 database, trying a few fallback locations.

    Returns:
    geoip2.database.Reader or None if no database could be opened
    """
    try:
        if geoip_db_path and os.path.exists(geoip_db_path):
            print(f"Successfully loaded GeoLite2 database from {geoip_db_path}")
            return geoip2.database.Reader(geoip_db_path)
        print(f"GeoLite2 database not found at {geoip_db_path}. Trying other locations...")
        # Try alternate locations
        alt_paths = [
            "./attached_assets/GeoLite2-City.mmdb",
            "GeoLite2-City.mmdb",
            "./GeoLite2-City.mmdb",
            "../attached_assets/GeoLite2-City.mmdb",
            "/attached_assets/GeoLite2-City.mmdb",
        ]
        for alt_path in alt_paths:
            if os.path.exists(alt_path):
                print(f"Successfully loaded GeoLite2 database from {alt_path}")
                return geoip2.database.Reader(alt_path)
        print("GeoLite2 database not found in any location. IP geolocation will be limited.")
    except Exception as e:
        print(f"Error opening GeoIP database: {e}")
    return None

def load_audit_dataframe(file_path):
    """Read a CSV or Excel audit log export into a DataFrame."""
    file_extension = os.path.splitext(file_path)[1].lower()

    if file_extension == '.csv':
        return pd.read_csv(file_path)
    elif file_extension in ['.xlsx', '.xls']:
        return pd.read_excel(file_path)
    raise ValueError(f"Unsupported file format: {file_extension}")

def build_timeline(df, geo_reader=None):
    """
    Turn an audit log DataFrame into a timeline of events with geolocation data.

    Parameters:
    df (DataFrame): Audit log rows with the REQUIRED_COLUMNS
    geo_reader: GeoLite2 database reader object (optional)

    Returns:
    list: Timeline of events with geolocation data
    """
    # Select relevant columns if they exist
    for col in REQUIRED_COLUMNS:
        if col not in df.columns:
            raise ValueError(f"Required column '{col}' not found in the input file")

    df = df[REQUIRED_COLUMNS].copy()

    # Convert CreationDate to datetime for sorting
    df['CreationDate'] = pd.to_datetime(df['CreationDate'])
    df = df.sort_values(by='CreationDate')

    # Parse AuditData and create a timeline with geolocation data
    timeline = []
    # Keep track of IPs we've already looked up to avoid repeated lookups
    ip_geo_cache = {}

    for _, row in df.iterrows():
        try:
            # Check if AuditData is a string, if so, parse it
            audit_data = row['AuditData']
            if isinstance(audit_data, str):
                audit_data = json.loads(audit_data)
            if not isinstance(audit_data, dict):
                # If it doesn't hold a JSON object, skip this row
                continue

            event = {
                'Timestamp': row['CreationDate'],
                'Operation': row['Operation'],
                'UserId': row['UserId'],
                'ClientIP': audit_data.get('ClientIP', 'N/A'),
                'ResultStatus': audit_data.get('ResultStatus', 'N/A')
            }

            # For FileAccessed events, extract the file name if available
            if row['Operation'] == 'FileAccessed':
                event['FileName'] = audit_data.get('SourceFileName', 'N/A')
            else:
                event['FileName'] = ''

            # Lookup geolocation info for the IP (if possible)
            ip = event['ClientIP']

            # Use our cache to avoid looking up the same IP multiple times
            if ip in ip_geo_cache:
                event.update(ip_geo_cache[ip])
            else:
                # Get geolocation data and cache it
                geo_data = get_ip_geolocation(ip, geo_reader)
                ip_geo_cache[ip] = geo_data
                event.update(geo_data)

            timeline.append(event)
        except json.JSONDecodeError:
            print(f"Error parsing AuditData for record at {row['CreationDate']}")

    return timeline

def parse_audit_logs(file_path, geoip_db_path=DEFAULT_GEOIP_DB_PATH):
    """
    Parse audit logs from CSV or Excel file and return a timeline of events with geolocation data.
    
    Parameters:
    file_path (str): Path to the input CSV or Excel file
    geoip_db_path (str): Path to the GeoLite2 database
    
    Returns:
    list: Timeline of events with geolocation data
    """
    geo_reader = open_geo_reader(geoip_db_path)
    try:
        return build_timeline(load_audit_dataframe(file_path), geo_reader)
    except Exception as e:
        print(f"Error processing file: {e}")
        raise
    finally:
        # Clean up geo reader
        if geo_reader:
            geo_reader.close()

def is_ip_anomalous(event):
    """
    Returns True if the event's IP is considered anomalous.
    An IP is NOT anomalous if it is exactly '192.168.1.160' (Frans usual IP).
    Otherwise, if the geolocated Country is not 'US' or the Region is not 'Massachusetts',
    then the event is considered anomalous.
    """
    ip = event.get('ClientIP', 'N/A')
    if ip == '192.168.1.160':
        return False
    country = event.get('Country', "Unknown")
    region = event.get('Region', "Unknown")
    # If the country is not USA or region is not Mass, flag as anomalous
    if country != 'US' or region != 'Massachusetts':
        return True
    return False

def detect_compromised_events(timeline):
    """
    Returns events exhibiting suspicious activity AND having an anomalous IP.
    Suspicious activity is defined as:
      - Operation is either 'SoftDelete' or 'MoveToDeletedItems'
      OR
      - The user has logged in from more than 3 unique IP addresses.
    """
    suspicious_ops = ['SoftDelete', 'MoveToDeletedItems']
    compromised_events = []
    user_ip_map = {}

    # First, build a map of unique IP addresses
    for event in timeline:
        user_id = event['UserId']
        client_ip = event['ClientIP']
        if user_id not in user_ip_map:
            user_ip_map[user_id] = set()
        user_ip_map[user_id].add(client_ip)

    # Flag an event as compromised if it looks like suspicious activity and has a weird IP
    for event in timeline:
        user_id = event['UserId']
        suspicious_activity = (event['Operation'] in suspicious_ops or len(user_ip_map[user_id]) > 3)
        if suspicious_activity and is_ip_anomalous(event):
            compromised_events.append(event)
    return compromised_events

def filter_files_accessed(timeline):
    """Return events where the operation is 'FileAccessed'."""
    return [event for event in timeline if event['Operation'] == 'FileAccessed']

def filter_anomalous_ips(timeline):
    """Return only events where the IP is considered anomalous per our criteria."""
    return [event for event in timeline if is_ip_anomalous(event)]

def assign_risk_level(event):
    """Assign a risk level (High/Medium/Low) to an event based on various factors."""
    risk_score = 0
    
    # Geographic risk
    country = event.get('Country', 'Unknown')
    if country in ['Unknown', 'CN', 'RU', 'KP', 'IR']:  # High-risk countries
        risk_score += 3
    elif country not in ['US', 'CA', 'GB', 'DE', 'FR', 'AU', 'JP']:  # Medium-risk countries
        risk_score += 2
    elif country == 'Local':
        risk_score += 0  # No additional risk for local IPs
    
    # Operation risk
    operation = event.get('Operation', '')
    high_risk_ops = ['SoftDelete', 'MoveToDeletedItems', 'UserLoginFailed', 'PasswordReset']
    medium_risk_ops = ['FileAccessed', 'FileModified', 'UserLogin']
    
    if operation in high_risk_ops:
        risk_score += 3
    elif operation in medium_risk_ops:
        risk_score += 1
    
    # Time-based risk (outside business hours)
    try:
        timestamp = pd.to_datetime(event.get('Timestamp'))
        hour = timestamp.hour
        weekday = timestamp.weekday()
        
        # Outside business hours (before 8 AM or after 6 PM)
        if hour < 8 or hour > 18:
            risk_score += 1
        
        # Weekend activity
        if weekday >= 5:  # Saturday = 5, Sunday = 6
            risk_score += 1
    except:
        pass
    
    # Determine risk level
    if risk_score >= 5:
        return 'High'
    elif risk_score >= 2:
        return 'Medium'
    else:
        return 'Low'

def classify_anomaly_type(event):
    """Classify the type of anomaly for an event."""
    anomaly_types = []
    
    # Geographic anomaly
    country = event.get('Country', 'Unknown')
    if country not in ['US', 'Local'] and is_ip_anomalous(event):
        anomaly_types.append('Geographic Anomaly')
    
    # Time anomaly
    try:
        timestamp = pd.to_datetime(event.get('Timestamp'))
        hour = timestamp.hour
        weekday = timestamp.weekday()
        
        if hour < 6 or hour > 22:  # Very unusual hours
            anomaly_types.append('Time Anomaly')
        elif weekday >= 5:  # Weekend activity
            anomaly_types.append('Time Anomaly')
    except:
        pass
    
    # Access pattern anomaly
    operation = event.get('Operation', '')
    suspicious_ops = ['SoftDelete', 'MoveToDeletedItems', 'PasswordReset']
    if operation in suspicious_ops:
        anomaly_types.append('Access Pattern Anomaly')
    
    # Failed authentication
    if 'Failed' in operation or 'Denied' in operation:
        anomaly_types.append('Failed Authentication')
    
    # Privilege escalation (if admin or elevated operations)
    if 'Admin' in operation or 'Elevate' in operation or 'Grant' in operation:
        anomaly_types.append('Privilege Escalation')
    
    return anomaly_types if anomaly_types else ['General Anomaly']

def apply_filters(events, filter_config):
    """Apply filtering configuration to a list of events."""
    if not events:
        return events
    
    filtered_events = []
    
    # Add risk level and anomaly type to each event
    for event in events:
        event_copy = event.copy()
        event_copy['RiskLevel'] = assign_risk_level(event_copy)
        event_copy['AnomalyTypes'] = classify_anomaly_type(event_copy)
        filtered_events.append(event_copy)
    
    # Apply risk level filter
    if filter_config.get('risk_levels'):
        filtered_events = [e for e in filtered_events if e['RiskLevel'] in filter_config['risk_levels']]
    
    # Apply anomaly type filter
    if filter_config.get('anomaly_types'):
        filtered_events = [e for e in filtered_events 
                          if any(atype in filter_config['anomaly_types'] for atype in e['AnomalyTypes'])]
    
    # Apply geographic filter
    if filter_config.get('excluded_countries'):
        filtered_events = [e for e in filtered_events 
                          if e.get('Country', 'Unknown') not in filter_config['excluded_countries']]
    
    # Apply time filter
    if filter_config.get('time_filter_type'):
        filtered_events = apply_time_filter(filtered_events, filter_config)
    
    # Apply IP pattern filter
    if filter_config.get('ip_filter_options'):
        filtered_events = apply_ip_pattern_filter(filtered_events, filter_config)
    
    return filtered_events

def apply_time_filter(events, filter_config):
    """Apply time-based filtering to events."""
    time_filter = filter_config.get('time_filter_type')
    if not time_filter:
        return events
    
    filtered_events = []
    for event in events:
        try:
            timestamp = pd.to_datetime(event.get('Timestamp'))
            hour = timestamp.hour
            weekday = timestamp.weekday()
            
            if time_filter == 'Business Hours Only':
                if 8 <= hour <= 17 and weekday < 5:  # Mon-Fri, 8 AM - 5 PM
                    filtered_events.append(event)
            elif time_filter == 'Outside Business Hours':
                if hour < 8 or hour > 17 or weekday >= 5:
                    filtered_events.append(event)
            elif time_filter == 'Weekends Only':
                if weekday >= 5:
                    filtered_events.append(event)
            elif time_filter == 'Custom Range':
                # Custom range filtering would need start_time and end_time
                start_time = filter_config.get('start_time')
                end_time = filter_config.get('end_time')
                if start_time and end_time:
                    event_time = timestamp.time()
                    if start_time <= event_time <= end_time:
                        filtered_events.append(event)
            else:
                filtered_events.append(event)
        except:
            filtered_events.append(event)  # Include events with invalid timestamps
    
    return filtered_events

def apply_ip_pattern_filter(events, filter_config):
    """Apply IP pattern-based filtering to events."""
    ip_options = filter_config.get('ip_filter_options', [])
    if not ip_options:
        return events
    
    # Count IP occurrences
    ip_counts = Counter(event.get('ClientIP', 'N/A') for event in events)
    
    # Get unique countries per IP
    ip_countries = {}
    for event in events:
        ip = event.get('ClientIP', 'N/A')
        country = event.get('Country', 'Unknown')
        if ip not in ip_countries:
            ip_countries[ip] = set()
        ip_countries[ip].add(country)
    
    filtered_events = []
    for event in events:
        ip = event.get('ClientIP', 'N/A')
        include_event = False
        
        for option in ip_options:
            if option == 'First-time IPs' and ip_counts[ip] == 1:
                include_event = True
            elif option == 'Frequent IPs' and ip_counts[ip] > 10:
                include_event = True
            elif option == 'Single-use IPs' and ip_counts[ip] == 1:
                include_event = True
            elif option == 'Cross-country IPs' and len(ip_countries[ip]) > 1:
                include_event = True
        
        if include_event or not ip_options:
            filtered_events.append(event)
    
    return filtered_events