# Development Guide - Microsoft Purview Security Analyzer

This guide covers the development setup and architecture of the Microsoft Purview Security Analyzer.

## Project Overview

The Microsoft Purview Security Analyzer is a comprehensive security audit log analysis tool built with Streamlit. It helps security professionals identify anomalous IP activities and potential security breaches in Microsoft Purview audit logs.

## Architecture

### Frontend
- **Framework**: Streamlit web application
- **Theme**: Dark mode optimized for security analysts
- **UI Components**: File upload, interactive maps, data tables, export functionality

### Backend
- **Core Logic**: Modular Python architecture
- **Data Processing**: CSV/Excel parsing with robust error handling
- **Analysis Engine**: IP geolocation, anomaly detection, event classification
- **Session Management**: Streamlit session state for performance optimization

### Key Components

```
microsoft-purview-security-analyzer/
├── app_new.py              # Main Streamlit application
├── security_analyzer.py   # Core analysis functions
├── attached_assets/        # Data files and assets
│   └── GeoLite2-City.mmdb # GeoIP database
├── .streamlit/
│   └── config.toml        # Streamlit configuration (dark theme)
└── docs/                  # Documentation files
```

## Development Setup

### Prerequisites
- Python 3.8 or higher
- Git
- Virtual environment (recommended)

### Local Development Environment

1. **Clone the repository**:
```bash
git clone https://github.com/umarcybr/microsoft-purview-security-analyzer.git
cd microsoft-purview-security-analyzer
```

2. **Create virtual environment**:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**:
```bash
pip install -e .
# or for development
pip install -e .[dev]
```

4. **Run the application**:
```bash
streamlit run app_new.py
```

## Code Structure

### Main Application (`app_new.py`)
- Streamlit UI setup and configuration
- File upload handling
- Session state management
- Data visualization coordination

### Analysis Engine (`security_analyzer.py`)
- Audit log parsing functions
- IP geolocation integration
- Anomaly detection algorithms
- Event classification logic

### Configuration (`.streamlit/config.toml`)
- Dark theme settings
- Server configuration
- UI customization

## Key Features Implementation

### Session State Management
Prevents unnecessary reprocessing when users interact with the map:
```python
if 'processed' not in st.session_state:
    st.session_state.processed = False
```

### Geolocation Integration
Uses local GeoLite2 database for fast IP lookups:
```python
def get_ip_location(ip_address):
    # GeoIP2 database lookup implementation
```

### Interactive Mapping
Folium integration with Streamlit for geospatial visualization:
```python
def create_map(anomalous_ips):
    # Interactive map generation
```

## Development Workflow

### Code Style
- Follow PEP 8 Python style guidelines
- Use meaningful variable and function names
- Add docstrings for all functions
- Keep functions focused and modular

### Testing
Currently manual testing is used. Run through this checklist:
- [ ] File upload (CSV/Excel formats)
- [ ] Map interaction without reloading
- [ ] Data table functionality
- [ ] Export capabilities
- [ ] Error handling with invalid files

### Performance Considerations
- **Large Files**: Implement progress bars for user feedback
- **Memory Usage**: Monitor with large datasets
- **Caching**: Leverage Streamlit's caching mechanisms
- **Database Lookups**: Optimize GeoIP queries

## Adding New Features

### New Analysis Algorithms
1. Add function to `security_analyzer.py`
2. Update the main processing pipeline in `app_new.py`
3. Add UI components for new results
4. Update documentation

### New Visualization Types
1. Import required libraries
2. Create visualization function
3. Add to appropriate tab in the UI
4. Test with sample data

### New File Formats
1. Add parsing logic to `security_analyzer.py`
2. Update file upload widget in `app_new.py`
3. Test with sample files
4. Update documentation

## Debugging

### Common Issues
- **Import Errors**: Check virtual environment activation
- **File Path Issues**: Verify GeoLite2 database location
- **Memory Errors**: Test with smaller sample files
- **UI Issues**: Check Streamlit version compatibility

### Logging
Add logging for debugging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
```

## Contributing

### Pull Request Process
1. Fork the repository
2. Create feature branch
3. Make changes with tests
4. Update documentation
5. Submit pull request

### Code Review Criteria
- Functionality works as expected
- Code follows style guidelines
- Documentation is updated
- No security vulnerabilities
- Performance impact considered

## Release Process

### Version Management
- Update version in `pyproject.toml` and `setup.py`
- Tag releases in Git
- Update CHANGELOG.md

### Distribution
- PyPI package (future consideration)
- GitHub releases with binaries
- Docker images for deployment

## Security Considerations

### Data Handling
- Never log sensitive information
- Validate all user inputs
- Secure file handling practices
- Follow OWASP guidelines

### Dependencies
- Regular security updates
- Vulnerability scanning
- Minimal dependency principle

## Performance Optimization

### Streamlit Specific
- Use `@st.cache_data` for expensive operations
- Implement session state properly
- Optimize file I/O operations

### Data Processing
- Vectorized operations with Pandas
- Efficient memory usage
- Progress indicators for long operations

This development guide should be updated as the project evolves and new features are added.
### Dashboard regression checks

Run `python -m unittest discover -s tests -v` from the repository root with the
application dependencies installed. Tests use synthetic CSV/XLSX audit logs and
Streamlit's AppTest harness; they cover result tables, repeated renders,
same-name replacement uploads, mixed timestamps, and bounded map summaries.

Map pins show a compact latest-event summary on hover. Click a pin or choose a
location below the map to browse all its events in a separate table. Events
without usable coordinates remain available in the event tables. Displayed
timestamps and time-based filters use UTC; timestamps without an offset are
interpreted as UTC. Unparseable timestamps display as Unknown.
