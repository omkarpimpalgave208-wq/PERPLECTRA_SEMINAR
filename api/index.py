"""
PERPLECTRA — Vercel Serverless Function entrypoint.

Exports the FastAPI ASGI application from server.py.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Add project root to sys.path so 'server' and 'perplectra' can be resolved
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from server import app

# Vercel's @vercel/python detects the ASGI/WSGI 'app' object
__all__ = ["app"]
