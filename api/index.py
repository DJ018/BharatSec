"""Vercel entry point: serves the BharatSec FastAPI app (backend/main.py) as one Python function."""
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from main import app  # noqa: E402
