"""
Configuration Settings for FastAPI Backend
"""

import os
from pathlib import Path
from typing import List

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Base directory
BASE_DIR = Path(__file__).resolve().parent

# Application metadata
PROJECT_TITLE = "AI-Based Scam Message Detection"
API_VERSION = "1.0.0"
DESCRIPTION = (
    "Production-grade FastAPI inference backend for B.Tech CSE AI-Based Scam Message Detection. "
    "Classifies SMS and Email messages using a trained scikit-learn FeatureUnion TF-IDF and LinearSVC pipeline."
)

# Environment detection
IS_PRODUCTION = (
    os.getenv("ENVIRONMENT", "").lower() in ("production", "prod")
    or bool(os.getenv("RENDER") or os.getenv("RAILWAY_ENVIRONMENT") or os.getenv("DYNO"))
)
DEBUG = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")

# Model configuration
MODEL_FILENAME = os.getenv("SCAM_MODEL_FILE", "scam_detection_pipeline.pkl")
MODEL_PATH = Path(os.getenv("MODEL_PATH", str(BASE_DIR / MODEL_FILENAME)))
if not MODEL_PATH.is_absolute():
    MODEL_PATH = BASE_DIR / MODEL_PATH

# Optional remote model artifact download URL (if model is hosted on S3, HuggingFace, R2, or GitHub release)
MODEL_DOWNLOAD_URL = os.getenv("MODEL_DOWNLOAD_URL") or os.getenv("MODEL_URL")

# Server settings (override with environment variables, e.g. $env:PORT="8005" or cloud $PORT)
# Default is 0.0.0.0 to support containerized/cloud deployments (Render, Railway, Heroku, Docker).
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8001"))

# CORS Allowed Origins
# Supports local frontend development servers (React, Vue, Vite, Next.js, Live Server)
DEFAULT_ORIGINS = [
    "https://project3-backend-fzlv.onrender.com",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:5500",
    "http://localhost:5501",
    "http://localhost:8000",
    "http://localhost:8001",
    "http://localhost:8080",
    "http://localhost:4200",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5500",
    "http://127.0.0.1:5501",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:8001",
    "http://127.0.0.1:8080",
    "null",
]

# Allow overriding via environment variable
ENV_ORIGINS = os.getenv("CORS_ORIGINS", "")
FRONTEND_URL = os.getenv("FRONTEND_URL", "").strip()

if ENV_ORIGINS:
    CORS_ORIGINS: List[str] = [origin.strip() for origin in ENV_ORIGINS.split(",") if origin.strip()]
else:
    CORS_ORIGINS: List[str] = list(DEFAULT_ORIGINS)

if FRONTEND_URL and FRONTEND_URL not in CORS_ORIGINS:
    CORS_ORIGINS.append(FRONTEND_URL)
