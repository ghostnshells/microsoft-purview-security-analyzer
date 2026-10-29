"""
Local development server: the API plus the front end in public/.

    uvicorn backend.dev:app --reload

On Vercel, public/ is served from the CDN, so the production app in
backend/server.py must not mount it.
"""

import os

from fastapi.staticfiles import StaticFiles

from backend.server import app

PUBLIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "public")

app.mount("/", StaticFiles(directory=PUBLIC_DIR, html=True), name="public")
