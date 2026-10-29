import streamlit as st
import pandas as pd
import folium
from streamlit_folium import st_folium
import tempfile
import os
import json
import hashlib
from dashboard_views import event_table, group_locations, create_activity_map
from security_analyzer import parse_audit_logs, detect_compromised_events, filter_files_accessed, filter_anomalous_ips, apply_filters

# Initialize session state variables to store processed data between re-renders
if 'processed' not in st.session_state:
    st.session_state.processed = False
if 'timeline' not in st.session_state:
    st.session_state.timeline = None
if 'compromised_events' not in st.session_state:
    st.session_state.compromised_events = None
if 'files_accessed' not in st.session_state:
    st.session_state.files_accessed = None
if 'anomalous_ips' not in st.session_state:
    st.session_state.anomalous_ips = None

# Set page configuration
st.set_page_config(
    page_title="Microsoft Purview Security Analyzer",
    page_icon="🔒",
    layout="wide"
)

# Title and description
st.title("Microsoft Purview Security Analyzer")
st.markdown("""
This tool helps identify anomalous IP activities and potentially compromised events in audit logs.
Upload your CSV or Excel file to analyze the data and visualize suspicious activities on the map.
""")

# Add file upload widget
uploaded_file = st.file_uploader("Upload CSV or Excel file", type=["csv", "xlsx", "xls"])

# Add filtering options in sidebar
st.sidebar.header("🔍 Anomaly Filters")
st.sidebar.markdown("Customize which types of anomalies to display:")

# Initialize filter states if not already set
if 'filter_by_risk_level' not in st.session_state:
    st.session_state.filter_by_risk_level = ['High', 'Medium', 'Low']
if 'filter_by_operation' not in st.session_state:
    st.session_state.filter_by_operation = []
if 'filter_by_country' not in st.session_state:
    st.session_state.filter_by_country = []
if 'filter_by_date_range' not in st.session_state:
    st.session_state.filter_by_date_range = False

# Risk Level Filter
st.sidebar.subheader("Risk Level")
risk_levels = st.sidebar.multiselect(
    "Select risk levels to display:",
    options=['High', 'Medium', 'Low'],
    default=st.session_state.filter_by_risk_level,
    key='risk_filter'
)
st.session_state.filter_by_risk_level = risk_levels

# Anomaly Type Filter
st.sidebar.subheader("Anomaly Types")
anomaly_types = st.sidebar.multiselect(
    "Select anomaly types:",
    options=['Geographic Anomaly', 'Time Anomaly', 'Access Pattern Anomaly', 'Failed Authentication', 'Privilege Escalation'],
    default=[],
    key='anomaly_type_filter'
)

# Geographic Filter
st.sidebar.subheader("Geographic Filter")
enable_geo_filter = st.sidebar.checkbox("Filter by geographic location", value=False)
if enable_geo_filter:
    excluded_countries = st.sidebar.multiselect(
        "Exclude countries:",
        options=['Unknown', 'Local', 'US', 'CA', 'GB', 'DE', 'FR', 'JP', 'AU'],
        default=['Local'],
        help="Select countries to exclude from results"
    )
else:
    excluded_countries = []

# Time-based Filter
st.sidebar.subheader("Time Filter")
enable_time_filter = st.sidebar.checkbox("Filter by time period", value=False)
if enable_time_filter:
    time_filter_type = st.sidebar.selectbox(
        "Time filter type:",
        options=['Business Hours Only', 'Outside Business Hours', 'Weekends Only', 'Custom Range']
    )
    if time_filter_type == 'Custom Range':
        col1, col2 = st.sidebar.columns(2)
        with col1:
            start_time = st.time_input("Start time", value=None)
        with col2:
            end_time = st.time_input("End time", value=None)
else:
    time_filter_type = None

# IP Pattern Filter
st.sidebar.subheader("IP Pattern Filter")
enable_ip_filter = st.sidebar.checkbox("Filter by IP patterns", value=False)
if enable_ip_filter:
    ip_filter_options = st.sidebar.multiselect(
        "IP pattern types:",
        options=['First-time IPs', 'Frequent IPs', 'Single-use IPs', 'Cross-country IPs'],
        default=[],
        help="Filter based on IP usage patterns"
    )
else:
    ip_filter_options = []

# Reset filters button
if st.sidebar.button("Reset All Filters"):
    st.session_state.filter_by_risk_level = ['High', 'Medium', 'Low']
    st.session_state.filter_by_operation = []
    st.session_state.filter_by_country = []
    st.session_state.filter_by_date_range = False
    st.rerun()

# Function to save uploaded file temporarily
def save_uploaded_file(uploaded_file):
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_file.name)[1]) as tmp:
            tmp.write(uploaded_file.getvalue())
            return tmp.name
    except Exception as e:
        st.error(f"Error saving file: {e}")
        return None

# Function to process the data (only runs when we need to)
def process_data(file_path):
    # Set up a progress bar for file processing
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    # Process the file with progress updates
    status_text.text("Reading and parsing the file...")
    progress_bar.progress(10)
    
    # Parse the audit logs with our optimized geolocation service
    timeline = parse_audit_logs(file_path)
    
    if not timeline:
        progress_bar.progress(100)
        status_text.text("")
        st.error("No data could be processed from the file. Please check the file format.")
        return False
    
    status_text.text("Processing IP geolocation data...")
    progress_bar.progress(50)
    
    # Continue with analysis
    status_text.text("Analyzing anomalies and generating insights...")
    progress_bar.progress(80)
    
    # Extract insights
    timeline = apply_filters(timeline, {})
    compromised_events = detect_compromised_events(timeline)
    files_accessed = filter_files_accessed(timeline)
    anomalous_ips = filter_anomalous_ips(timeline)
    
    # Store results in session state
    st.session_state.timeline = timeline
    st.session_state.compromised_events = compromised_events
    st.session_state.files_accessed = files_accessed
    st.session_state.anomalous_ips = anomalous_ips
    st.session_state.processed = True
    
    # Complete the progress bar
    progress_bar.progress(100)
    status_text.text("")
    st.success(f"Successfully processed {len(timeline)} events.")
    return True

# Main application logic
if uploaded_file is not None:
    try:
        # Reset session state if a new file is uploaded
        current_file = getattr(st.session_state, 'current_file', None) 
        file_identity = hashlib.sha256(uploaded_file.getbuffer()).hexdigest()
        if current_file != file_identity:
            st.session_state.processed = False
            st.session_state.current_file = file_identity
        
        # Only process the file if we haven't already done so for this file
        if not st.session_state.processed:
            # Save uploaded file temporarily
            temp_file_path = save_uploaded_file(uploaded_file)
            # Process the file only if we have a valid file path
            if temp_file_path:
                try:
                    process_data(temp_file_path)
                finally:
                    if os.path.exists(temp_file_path):
                        os.unlink(temp_file_path)
            else:
                st.error("Failed to save uploaded file. Please try again.")
        
        # If processing was successful, display the results
        if st.session_state.processed and st.session_state.timeline is not None:
            # Get data from session state
            timeline = st.session_state.timeline
            compromised_events = st.session_state.compromised_events or []
            files_accessed = st.session_state.files_accessed or []
            anomalous_ips = st.session_state.anomalous_ips or []
            
            # Apply custom filters
            filter_config = {
                'risk_levels': risk_levels,
                'anomaly_types': anomaly_types,
                'excluded_countries': excluded_countries,
                'time_filter_type': time_filter_type if enable_time_filter else None,
                'ip_filter_options': ip_filter_options if enable_ip_filter else [],
            }
            
            # Add custom time range if applicable
            if enable_time_filter and time_filter_type == 'Custom Range':
                if 'start_time' in locals() and 'end_time' in locals():
                    filter_config['start_time'] = start_time
                    filter_config['end_time'] = end_time
            
            # Apply filters to each dataset
            filtered_compromised = apply_filters(compromised_events, filter_config)
            filtered_files_accessed = apply_filters(files_accessed, filter_config) 
            filtered_anomalous_ips = apply_filters(anomalous_ips, filter_config)
            filtered_timeline = apply_filters(timeline, filter_config)
            
            # Update variables to use filtered data
            compromised_events = filtered_compromised
            files_accessed = filtered_files_accessed
            anomalous_ips = filtered_anomalous_ips
            timeline_filtered = filtered_timeline
            
            # Display filter summary if filters are active
            active_filters = []
            if risk_levels and len(risk_levels) < 3:
                active_filters.append(f"Risk: {', '.join(risk_levels)}")
            if anomaly_types:
                active_filters.append(f"Types: {', '.join(anomaly_types)}")
            if excluded_countries:
                active_filters.append(f"Excluded: {', '.join(excluded_countries)}")
            if enable_time_filter:
                active_filters.append(f"Time: {time_filter_type}")
            if enable_ip_filter and ip_filter_options:
                active_filters.append(f"IP: {', '.join(ip_filter_options)}")
            
            if active_filters:
                st.info(f"🔍 **Active Filters:** {' | '.join(active_filters)}")
            
            # Display summary statistics
            col1, col2, col3, col4 = st.columns(4)
            total_before = len(st.session_state.timeline)
            col1.metric("Total Events", f"{len(timeline_filtered)}", delta=f"{len(timeline_filtered) - total_before}" if active_filters else None)
            col2.metric("Suspicious Events", len(compromised_events))
            col3.metric("Files Accessed", len(files_accessed))
            col4.metric("Anomalous IPs", len({event.get("ClientIP") for event in anomalous_ips}))
            
            # Create tabs for different views
            tab1, tab2, tab3, tab4 = st.tabs(["Map View", "Suspicious Events", "Files Accessed", "All Events"])
            
            with tab1:
                st.subheader("Anomalous IP Activity Map")
                st.caption("Hover for the latest time, action and location. Click a pin to browse its events below; zoom into clusters to select a pin. Times are UTC.")
                groups = group_locations(anomalous_ips)
                if groups:
                    if st.session_state.get('map_events') != anomalous_ips:
                        st.session_state.activity_map = create_activity_map(groups)
                        st.session_state.map_events = anomalous_ips
                    result = st_folium(st.session_state.activity_map, height=520,
                                       use_container_width=True, key="activity_map",
                                       returned_objects=["last_object_clicked"])
                    selected = result.get("last_object_clicked") if result else None
                    keys = list(groups)
                    if selected and selected != st.session_state.get('last_map_click'):
                        st.session_state.last_map_click = selected
                        closest = min(keys, key=lambda p: abs(p[0]-selected['lat']) + abs(p[1]-selected['lng']))
                        st.session_state.selected_location = closest
                    saved = st.session_state.get('selected_location')
                    index = keys.index(saved) if saved in keys else 0
                    location = st.selectbox("Location events", keys, index=index,
                        format_func=lambda p: f"{groups[p][0].get('City', 'Unknown')}, {groups[p][0].get('Region', 'Unknown')}, {groups[p][0].get('Country', 'Unknown')} · {len(groups[p]):,} events · {p[0]:.3f}, {p[1]:.3f}")
                    st.dataframe(event_table(groups[location]), use_container_width=True, hide_index=True)
                else:
                    st.info("No geolocated anomalous events match the current filters.")
                omitted = len(anomalous_ips) - sum(map(len, groups.values()))
                if omitted:
                    st.caption(f"{omitted:,} events have no usable map coordinates. They remain in the event tables.")
                with st.expander("All anomalous IP events"):
                    st.dataframe(event_table(anomalous_ips), use_container_width=True, hide_index=True)

            for tab, title, events in [(tab2, "Suspicious Events", compromised_events),
                                       (tab3, "Files Accessed", files_accessed),
                                       (tab4, "All Events", timeline_filtered)]:
                with tab:
                    st.subheader(title)
                    if events:
                        st.dataframe(event_table(events), use_container_width=True, hide_index=True)
                    else:
                        st.info("No events match the current filters.")

            # Option to download results
            st.subheader("Download Results")
            
            # Prepare data for download
            output = {
                "timeline": timeline_filtered,
                "compromised_events": compromised_events,
                "files_accessed": files_accessed,
                "anomalous_ips": anomalous_ips
            }
            
            # Convert to JSON for download
            json_data = json.dumps(output, default=str)
            st.download_button(
                label="Download Results as JSON",
                data=json_data,
                file_name="security_analysis_results.json",
                mime="application/json"
            )
    
    except Exception as e:
        st.error(f"An error occurred during processing: {str(e)}")
        import traceback
        st.error(traceback.format_exc())
else:
    # Display instructions when no file is uploaded
    st.info("Please upload a CSV or Excel file containing audit logs to begin analysis.")
    
    # Show example of expected data format
    st.subheader("Expected Data Format")
    st.markdown("""
    The uploaded file should contain audit log data with at least the following columns:
    - CreationDate: Timestamp of the event
    - Operation: Type of operation performed
    - UserId: User identifier
    - AuditData: JSON data containing details like ClientIP
    
    Other columns will be used if available but are not required.
    """)
    
    # Show sample of the analysis capabilities
    st.subheader("Analysis Capabilities")
    st.markdown("""
    This tool will:
    1. Identify anomalous IP addresses based on geolocation
    2. Detect potentially compromised events
    3. Track file access operations
    4. Visualize suspicious activities on an interactive map
    5. Provide detailed tables of all events for further investigation
    """)