# Deployment Guide - Microsoft Purview Security Analyzer

This guide covers various deployment options for the Microsoft Purview Security Analyzer.

## Local Development

### Quick Start
```bash
git clone https://github.com/umarcybr/microsoft-purview-security-analyzer.git
cd microsoft-purview-security-analyzer
pip install streamlit pandas folium streamlit-folium geoip2 openpyxl trafilatura
streamlit run app_new.py
```

### Web app (FastAPI + browser front end)
```bash
pip install fastapi uvicorn pandas geoip2 openpyxl
uvicorn backend.dev:app --reload
```
Then open http://localhost:8000. This is the same app that runs on Vercel.

## Production Deployment Options

### Vercel

The web app runs on Vercel without extra configuration. Streamlit cannot: it needs a
long-running server with WebSockets, which Vercel Functions don't provide.

**How it is laid out**:
- `backend/server.py`: FastAPI app (the Vercel entrypoint, set in `[tool.vercel]` in `pyproject.toml`). It runs the analysis in `security_analyzer.py`.
- `public/`: the front end (HTML, CSS, JS, plus vendored Leaflet and PapaParse), served from Vercel's CDN.
- `vercel.json`: keeps the front end, images and docs out of the Python function bundle. The GeoLite2 database stays in.

**Steps**:
1. Import the repository in Vercel (or run `vercel deploy`)
2. Leave the framework preset on FastAPI; no build command or environment variables are needed

**Limits to know**:
- Vercel caps request bodies at 4.5 MB. CSV exports are trimmed in the browser to the four columns and three AuditData fields the analysis reads, then gzipped, so exports of tens of MB fit. Excel files are sent as-is, so they are limited to about 4.4 MB; export CSV from Purview for larger logs.
- Responses are gzip-compressed and sent column-wise to stay under the same cap.
- Each request is analyzed independently and nothing is stored on the server. Filters run in the browser.

### 1. Streamlit Cloud (Recommended)

**Pros**: Free, easy setup, automatic HTTPS, custom domains
**Cons**: Resource limitations, public repositories only

**Steps**:
1. Push your code to GitHub
2. Visit [share.streamlit.io](https://share.streamlit.io)
3. Connect your GitHub repository
4. Deploy with one click

**Requirements**:
- Public GitHub repository
- Configure secrets for any API keys if needed

### 2. Heroku

**Pros**: Reliable, scalable, add-ons available
**Cons**: Paid service, requires some configuration

**Setup**:
```bash
# Create Procfile
echo "web: streamlit run app_new.py --server.port \$PORT --server.address 0.0.0.0" > Procfile

# Create runtime.txt
echo "python-3.11.0" > runtime.txt

# Deploy
heroku create your-app-name
git push heroku main
```

### 3. Docker Container

**Pros**: Consistent environment, works anywhere
**Cons**: Requires Docker knowledge

**Dockerfile**:
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install streamlit pandas folium streamlit-folium geoip2 openpyxl trafilatura

EXPOSE 8501

CMD ["streamlit", "run", "app_new.py", "--server.address", "0.0.0.0"]
```

**Build and run**:
```bash
docker build -t purview-analyzer .
docker run -p 8501:8501 purview-analyzer
```

### 4. AWS EC2

**Pros**: Full control, scalable, professional
**Cons**: Requires AWS knowledge, costs money

**Setup on Ubuntu EC2**:
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and pip
sudo apt install python3 python3-pip -y

# Clone and setup
git clone https://github.com/yourusername/microsoft-purview-security-analyzer.git
cd microsoft-purview-security-analyzer
pip3 install streamlit pandas folium streamlit-folium geoip2 openpyxl trafilatura

# Run with nohup for background execution
nohup streamlit run app_new.py --server.address 0.0.0.0 --server.port 8501 &
```

### 5. Google Cloud Platform

**Pros**: Google infrastructure, auto-scaling
**Cons**: Complex setup, costs money

Use Google Cloud Run or App Engine for deployment.

## Configuration for Production

### Environment Variables
Create `.env` file for production settings:
```bash
STREAMLIT_SERVER_PORT=8501
STREAMLIT_SERVER_ADDRESS=0.0.0.0
STREAMLIT_THEME_BASE=dark
```

### Performance Optimization

1. **Memory Management**:
   - Monitor memory usage with large files
   - Implement file size limits if needed
   - Use chunked processing for very large datasets

2. **Caching**:
   - Streamlit's @st.cache_data is already implemented
   - Consider Redis for multi-user deployments

3. **Security**:
   - Use HTTPS in production
   - Implement file upload limits
   - Validate all user inputs
   - Consider authentication for sensitive deployments

### Load Balancing

For high-traffic deployments:

**Nginx Configuration**:
```nginx
upstream streamlit {
    server 127.0.0.1:8501;
    server 127.0.0.1:8502;
    server 127.0.0.1:8503;
}

server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://streamlit;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Monitoring and Maintenance

### Health Checks
Add health check endpoint in Streamlit:
```python
# Add to app_new.py
if st.query_params.get("health") == "check":
    st.write("OK")
    st.stop()
```

### Logging
```python
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
```

### Updates
- Monitor dependencies for security updates
- Test new Streamlit versions before upgrading
- Backup user data and configurations

## Troubleshooting Common Issues

### Memory Errors
- Increase server memory
- Implement file size limits
- Use streaming for large files

### Port Issues
- Check firewall settings
- Ensure port is open in security groups (AWS)
- Use environment variables for port configuration

### SSL/HTTPS Issues
- Use reverse proxy (Nginx/Apache)
- Configure SSL certificates
- Update Streamlit server settings

## Cost Optimization

### Free Options
1. **Streamlit Cloud**: Best for open-source projects
2. **Heroku Free Tier**: Limited hours but functional
3. **GitHub Codespaces**: Development and testing

### Paid Optimizations
1. **Right-size instances**: Don't over-provision
2. **Auto-scaling**: Scale down during low usage
3. **CDN**: For static assets and global reach

## Security Considerations

### Data Protection
- Never log sensitive information
- Encrypt data in transit and at rest
- Implement proper access controls

### GDPR Compliance
- Add privacy policy if handling EU data
- Implement data deletion capabilities
- Document data processing activities

### Regular Security Updates
- Monitor CVE databases
- Update dependencies regularly
- Perform security audits

## Support and Maintenance

### Backup Strategy
- Code: GitHub repository
- Data: Regular database backups if applicable
- Configuration: Document all settings

### Update Process
1. Test updates in staging environment
2. Schedule maintenance windows
3. Have rollback plan ready
4. Monitor post-deployment

For questions about deployment, please open an issue on the GitHub repository.