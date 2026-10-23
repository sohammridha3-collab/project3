"""
Configuration Settings for FastAPI Backend
"""

import os
from pathlib import Path
from typing import List

# Base directory
BASE_DIR = Path(__file__).resolve().parent

# Application metadata
PROJECT_TITLE = "AI-Based Scam Message Detection"
API_VERSION = "1.0.0"
DESCRIPTION = (
    "Production-grade FastAPI inference backend for B.Tech CSE AI-Based Scam Message Detection. "
    "Classifies SMS and Email messages using a trained scikit-learn FeatureUnion TF-IDF and LinearSVC pipeline."
)

# Model configuration
MODEL_FILENAME = os.getenv("SCAM_MODEL_FILE", "scam_detection_pipeline.pkl")
MODEL_PATH = BASE_DIR / MODEL_FILENAME

# Server settings (override with environment variables, e.g. $env:PORT="8005")
# Default is 8001 because port 8000 is commonly occupied by other local projects.
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8001"))

# CORS Allowed Origins
# Supports local frontend development servers (React, Vue, Vite, Next.js, Live Server)
DEFAULT_ORIGINS = [
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
if ENV_ORIGINS:
    CORS_ORIGINS: List[str] = [origin.strip() for origin in ENV_ORIGINS.split(",") if origin.strip()]
else:
    CORS_ORIGINS: List[str] = DEFAULT_ORIGINS
