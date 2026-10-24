"""
FastAPI Backend for ScamShield AI — Intelligent Scam Message Detection System
Full-stack REST API with Model Inference, Authentication, Scan History, PDF Reports, and Static File Serving.
"""

import os
import json
import logging
from contextlib import asynccontextmanager
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException, status, Request, Depends, Query, Response, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_


import tempfile

from config import PROJECT_TITLE, API_VERSION, DESCRIPTION, CORS_ORIGINS, HOST, PORT, BASE_DIR, IS_PRODUCTION
from database import get_db, init_db
from db_models import User, ScanRecord, CallScanRecord
from auth_utils import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
    get_optional_user
)
from report_service import generate_scan_pdf_report, generate_call_pdf_report
from schemas import (
    MessageInput,
    BatchMessageInput,
    PredictionResult,
    BatchPredictionResponse,
    ModelInfoResponse,
    HealthResponse,
    UserRegister,
    UserLogin,
    UserResponse,
    TokenResponse,
    ScanRecordResponse,
    ScanStatsResponse,
    CallScanResponse,
    UrlScanRequest,
    UrlScanResponse
)
from model_service import get_model_service, ModelLoadError
from call_service import validate_audio_file, analyze_call_audio
from url_scanner_service import scan_url, SsrfBlockError

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("scamshield.api")


# Lifespan: initialize database and load ML pipeline once at application start
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing ScamShield AI FastAPI Service...")
    # 1. Initialize SQLite / PostgreSQL Database
    try:
        init_db()
        logger.info("✅ Database tables verified and initialized.")
    except Exception as db_exc:
        logger.error(f"❌ Database initialization failed: {db_exc}", exc_info=True)

    # 2. Load ML model pipeline
    model_service = get_model_service()
    try:
        model_service.load_model()
        logger.info("✅ ML model pipeline successfully loaded and ready for inference.")
    except ModelLoadError as exc:
        logger.error(f"❌ Failed to load model pipeline at startup: {exc}")

    yield
    logger.info("Shutting down ScamShield AI FastAPI service...")


# Initialize FastAPI app
app = FastAPI(
    title=PROJECT_TITLE,
    version=API_VERSION,
    description=DESCRIPTION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS Middleware
cors_origins_to_use = CORS_ORIGINS
cors_has_wildcard = "*" in cors_origins_to_use

cors_kwargs: Dict[str, Any] = {
    "allow_methods": ["*"],
    "allow_headers": ["*"],
}

if cors_has_wildcard:
    cors_kwargs["allow_origins"] = ["*"]
    cors_kwargs["allow_credentials"] = False
else:
    cors_kwargs["allow_origins"] = cors_origins_to_use
    cors_kwargs["allow_credentials"] = True
    cors_kwargs["allow_origin_regex"] = r"https?://(localhost|127\.0\.0\.1|.*\.onrender\.com|.*\.railway\.app|.*\.vercel\.app|.*\.netlify\.app|.*\.github\.io)(:\d+)?"

app.add_middleware(CORSMiddleware, **cors_kwargs)


# Exception Handlers
@app.exception_handler(ModelLoadError)
async def model_load_exception_handler(request: Request, exc: ModelLoadError):
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "error": "ModelUnavailable",
            "message": str(exc),
            "remediation": "Ensure 'scam_detection_pipeline.pkl' is present in the backend directory."
        }
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    # Check if error is caused by invalid JSON body decoding
    for err in errors:
        msg = err.get("msg", "")
        err_type = err.get("type", "")
        loc = err.get("loc", ())
        if err_type in ("json_invalid", "value_error.jsondecode") or "JSON decode error" in msg:
            ctx_err = err.get("ctx", {}).get("error", "Malformed or unparseable JSON payload")
            logger.warning(f"JSON decode error on {request.method} {request.url.path}: {ctx_err}")
            return JSONResponse(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                content={
                    "error": "InvalidJsonBody",
                    "detail": f"Invalid JSON in request body ({ctx_err}). Please ensure the request body is valid JSON with header 'Content-Type: application/json'."
                }
            )

    # Format other field-level validation errors cleanly
    formatted_errors = []
    for err in errors:
        loc = [str(l) for l in err.get("loc", []) if l != "body"]
        loc_str = " -> ".join(loc)
        msg = err.get("msg", "Validation error")
        formatted_errors.append(f"{loc_str}: {msg}" if loc_str else msg)

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "ValidationError",
            "detail": "; ".join(formatted_errors)
        }
    )


# =============================================================================
# AUTHENTICATION ENDPOINTS
# =============================================================================

@app.post("/api/auth/register", response_model=TokenResponse, tags=["Authentication"])
async def register_user(payload: UserRegister, db: Session = Depends(get_db)):
    """Registers a new user, hashes password with PBKDF2-SHA256, and returns a JWT token."""
    existing = db.query(User).filter(User.email == payload.email.lower().strip()).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists. Please log in."
        )

    hashed = hash_password(payload.password)
    new_user = User(
        full_name=payload.full_name.strip(),
        email=payload.email.lower().strip(),
        hashed_password=hashed
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = create_access_token({"sub": str(new_user.id), "email": new_user.email})
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(new_user)
    )


@app.post("/api/auth/login", response_model=TokenResponse, tags=["Authentication"])
async def login_user(payload: UserLogin, db: Session = Depends(get_db)):
    """Authenticates a user and returns a signed JWT access token."""
    user = db.query(User).filter(User.email == payload.email.lower().strip()).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password. Please check your credentials."
        )

    token = create_access_token({"sub": str(user.id), "email": user.email})
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
    )


@app.get("/api/auth/me", response_model=UserResponse, tags=["Authentication"])
async def get_current_user_profile(user: User = Depends(get_current_user)):
    """Returns profile information for the currently authenticated user."""
    return UserResponse.model_validate(user)


# =============================================================================
# MACHINE LEARNING INFERENCE ENDPOINTS
# =============================================================================

@app.post("/predict", response_model=PredictionResult, tags=["Inference"])
@app.post("/api/predict", response_model=PredictionResult, tags=["Inference"])
async def predict_message(
    payload: MessageInput,
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db)
):
    """
    Predicts whether a single message (SMS, Email, or raw text) is scam/phishing or legitimate.
    If the request is authenticated, the scan is automatically persisted to the user's history.
    """
    service = get_model_service()
    if not service.is_loaded:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML model pipeline is not currently loaded."
        )

    processed_text = payload.get_processed_text()
    if not processed_text:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Message content cannot be empty."
        )

    try:
        result = service.predict_single(processed_text)
        scan_id = None

        # Automatically persist scan if user is authenticated
        if user is not None:
            scan_rec = ScanRecord(
                user_id=user.id,
                message_text=processed_text,
                subject=payload.subject,
                message_type=payload.message_type or "auto",
                predicted_label=result["predicted_label"],
                predicted_class=result["predicted_class"],
                is_scam=result["is_scam"],
                confidence=result["confidence"],
                decision_margin=result.get("decision_margin"),
                risk_level=result["risk_level"],
                indicators_json=json.dumps(result.get("indicators_detected", []))
            )
            db.add(scan_rec)
            db.commit()
            db.refresh(scan_rec)
            scan_id = scan_rec.id

        result["scan_id"] = scan_id
        return PredictionResult(**result)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(ve))
    except Exception as exc:
        logger.error(f"Prediction failed: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference execution failed: {str(exc)}"
        )


@app.post("/predict/batch", response_model=BatchPredictionResponse, tags=["Inference"])
@app.post("/api/predict/batch", response_model=BatchPredictionResponse, tags=["Inference"])
async def predict_batch(payload: BatchMessageInput):
    """Classifies multiple messages in a high-throughput batch request (up to 100 items)."""
    service = get_model_service()
    if not service.is_loaded:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML model pipeline is not currently loaded."
        )

    texts: List[str] = [msg.get_processed_text() or " " for msg in payload.messages]
    try:
        batch_result = service.predict_batch(texts)
        return BatchPredictionResponse(**batch_result)
    except Exception as exc:
        logger.error(f"Batch prediction failed: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch inference execution failed: {str(exc)}"
        )


# =============================================================================
# URL & WEBSITE SCANNER ENDPOINT (SSRF-PROTECTED)
# =============================================================================

@app.post("/api/url-scan", response_model=UrlScanResponse, tags=["URL Scanner"])
async def scan_website_url(
    payload: UrlScanRequest,
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db)
):
    """
    Performs deterministic, SSRF-safe analysis of a website URL.
    - Inspects structural indicators, punycode, misleading userinfo (@), and IP hosts.
    - Inspects HTTPS status and verifies TLS certificates safely.
    - Checks live reputation feeds if configured (transparently reports when not configured).
    - Safely traces HTTP redirects enforcing strict timeouts, size limits, and per-hop SSRF validation.
    - Computes deterministic threat risk score and outputs actionable defense recommendations.
    - If user is authenticated, preserves scan record in their isolated audit history.
    """
    if not payload.url or not payload.url.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="URL parameter cannot be empty."
        )

    try:
        result = scan_url(payload.url.strip())
    except SsrfBlockError as ssrf_err:
        logger.warning(f"Blocked SSRF attempt: {ssrf_err}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Security violation: Access to destination is prohibited by SSRF security policy ({str(ssrf_err)})."
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(ve)
        )
    except Exception as exc:
        logger.error(f"URL analysis failed: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while evaluating the destination URL. Please verify the URL and try again."
        )

    scan_id = None
    if user is not None:
        try:
            reg_dom = result.get("domain_info", {}).get("registered_domain") or result.get("domain_info", {}).get("host") or "URL"
            scan_rec = ScanRecord(
                user_id=user.id,
                message_text=result["url"],
                subject=f"URL: {reg_dom}",
                message_type="url",
                predicted_label=1 if result["classification"] in ("Suspicious", "High Risk") else 0,
                predicted_class=result["classification"],
                is_scam=result["classification"] in ("Suspicious", "High Risk"),
                confidence=result["risk_score"] / 100.0,
                decision_margin=None,
                risk_level=result["classification"].upper().replace(" ", "_"),
                indicators_json=json.dumps(result["findings"])
            )
            db.add(scan_rec)
            db.commit()
            db.refresh(scan_rec)
            scan_id = scan_rec.id
        except Exception as db_err:
            logger.error(f"Failed to persist URL scan history: {db_err}")
            db.rollback()

    result["scan_id"] = scan_id
    return UrlScanResponse(**result)


# =============================================================================
# SCAN HISTORY & USER STATS ENDPOINTS (PROTECTED)
# =============================================================================

@app.get("/api/scans/history", response_model=List[ScanRecordResponse], tags=["History"])
async def get_user_scan_history(
    filter_type: str = Query("all", pattern="^(all|scam|legitimate)$"),
    record_type: str = Query("all", pattern="^(all|message|call|url)$"),
    search: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns past scans (messages, audio call analyses, and URL scans) belonging solely to the logged-in user with search & filtering."""
    response_items = []

    # 1. Fetch Message Records (excluding URL scans)
    if record_type in ("all", "message"):
        msg_query = db.query(ScanRecord).filter(ScanRecord.user_id == user.id, ScanRecord.message_type != "url")
        if filter_type == "scam":
            msg_query = msg_query.filter(ScanRecord.is_scam == True)
        elif filter_type == "legitimate":
            msg_query = msg_query.filter(ScanRecord.is_scam == False)

        if search:
            search_term = f"%{search.strip()}%"
            msg_query = msg_query.filter(
                or_(
                    ScanRecord.message_text.ilike(search_term),
                    ScanRecord.subject.ilike(search_term)
                )
            )

        for r in msg_query.all():
            response_items.append(
                ScanRecordResponse(
                    id=r.id,
                    record_type="message",
                    user_id=r.user_id,
                    message_text=r.message_text,
                    subject=r.subject,
                    message_type=r.message_type or "sms",
                    predicted_label=r.predicted_label,
                    predicted_class=r.predicted_class,
                    is_scam=r.is_scam,
                    confidence=r.confidence,
                    confidence_percentage=f"{round(r.confidence * 100, 1)}%",
                    decision_margin=r.decision_margin,
                    risk_level=r.risk_level,
                    indicators_detected=r.indicators_list,
                    created_at=r.created_at
                )
            )

    # 2. Fetch URL Scan Records
    if record_type in ("all", "url"):
        url_query = db.query(ScanRecord).filter(ScanRecord.user_id == user.id, ScanRecord.message_type == "url")
        if filter_type == "scam":
            url_query = url_query.filter(ScanRecord.is_scam == True)
        elif filter_type == "legitimate":
            url_query = url_query.filter(ScanRecord.is_scam == False)

        if search:
            search_term = f"%{search.strip()}%"
            url_query = url_query.filter(
                or_(
                    ScanRecord.message_text.ilike(search_term),
                    ScanRecord.subject.ilike(search_term)
                )
            )

        for r in url_query.all():
            response_items.append(
                ScanRecordResponse(
                    id=r.id,
                    record_type="url",
                    user_id=r.user_id,
                    message_text=r.message_text,
                    subject=r.subject or "URL Scan",
                    message_type="url",
                    predicted_label=r.predicted_label,
                    predicted_class=r.predicted_class,
                    is_scam=r.is_scam,
                    confidence=r.confidence,
                    confidence_percentage=f"{round(r.confidence * 100, 1)}%",
                    decision_margin=r.decision_margin,
                    risk_level=r.risk_level,
                    indicators_detected=r.indicators_list,
                    created_at=r.created_at,
                    url=r.message_text,
                    normalized_url=r.message_text
                )
            )

    # 3. Fetch Call Records
    if record_type in ("all", "call"):
        call_query = db.query(CallScanRecord).filter(CallScanRecord.user_id == user.id)
        if filter_type == "scam":
            call_query = call_query.filter(CallScanRecord.is_scam == True)
        elif filter_type == "legitimate":
            call_query = call_query.filter(CallScanRecord.is_scam == False)

        if search:
            search_term = f"%{search.strip()}%"
            call_query = call_query.filter(
                or_(
                    CallScanRecord.transcript.ilike(search_term),
                    CallScanRecord.audio_filename.ilike(search_term),
                    CallScanRecord.language_name.ilike(search_term)
                )
            )

        for c in call_query.all():
            response_items.append(
                ScanRecordResponse(
                    id=c.id,
                    record_type="call",
                    user_id=c.user_id,
                    message_text=c.transcript,
                    subject=f"Audio Call: {c.audio_filename or 'Recording'}",
                    message_type="call",
                    predicted_label=1 if c.is_scam else 0,
                    predicted_class=c.predicted_class,
                    is_scam=c.is_scam,
                    confidence=c.confidence,
                    confidence_percentage=f"{round(c.confidence * 100, 1)}%",
                    decision_margin=None,
                    risk_level=c.risk_level,
                    indicators_detected=c.indicators_list,
                    created_at=c.created_at,
                    audio_filename=c.audio_filename,
                    detected_language=c.detected_language,
                    language_name=c.language_name,
                    transcript=c.transcript,
                    translated_transcript=c.translated_transcript,
                    duration_seconds=c.duration_seconds
                )
            )

    # Sort descending by creation timestamp
    response_items.sort(key=lambda x: x.created_at, reverse=True)
    return response_items[offset:offset + limit]


@app.get("/api/scans/stats", response_model=ScanStatsResponse, tags=["Dashboard"])
async def get_user_scan_stats(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Returns analytics and summary metrics combining messages, call scans, and URL scans for the user's dashboard."""
    msg_scans = db.query(ScanRecord).filter(ScanRecord.user_id == user.id).all()
    call_scans = db.query(CallScanRecord).filter(CallScanRecord.user_id == user.id).all()

    total = len(msg_scans) + len(call_scans)
    scam_count = sum(1 for s in msg_scans if s.is_scam) + sum(1 for c in call_scans if c.is_scam)
    legit_count = total - scam_count
    scam_pct = round((scam_count / total * 100), 1) if total > 0 else 0.0

    recent_items = []
    for r in msg_scans:
        rec_type = "url" if r.message_type == "url" else "message"
        recent_items.append(
            ScanRecordResponse(
                id=r.id,
                record_type=rec_type,
                user_id=r.user_id,
                message_text=r.message_text,
                subject=r.subject,
                message_type=r.message_type or "sms",
                predicted_label=r.predicted_label,
                predicted_class=r.predicted_class,
                is_scam=r.is_scam,
                confidence=r.confidence,
                confidence_percentage=f"{round(r.confidence * 100, 1)}%",
                decision_margin=r.decision_margin,
                risk_level=r.risk_level,
                indicators_detected=r.indicators_list,
                created_at=r.created_at,
                url=r.message_text if rec_type == "url" else None,
                normalized_url=r.message_text if rec_type == "url" else None
            )
        )

    for c in call_scans:
        recent_items.append(
            ScanRecordResponse(
                id=c.id,
                record_type="call",
                user_id=c.user_id,
                message_text=c.transcript,
                subject=f"Audio Call: {c.audio_filename or 'Recording'}",
                message_type="call",
                predicted_label=1 if c.is_scam else 0,
                predicted_class=c.predicted_class,
                is_scam=c.is_scam,
                confidence=c.confidence,
                confidence_percentage=f"{round(c.confidence * 100, 1)}%",
                decision_margin=None,
                risk_level=c.risk_level,
                indicators_detected=c.indicators_list,
                created_at=c.created_at,
                audio_filename=c.audio_filename,
                detected_language=c.detected_language,
                language_name=c.language_name,
                transcript=c.transcript,
                translated_transcript=c.translated_transcript,
                duration_seconds=c.duration_seconds
            )
        )

    recent_items.sort(key=lambda x: x.created_at, reverse=True)

    return ScanStatsResponse(
        total_scans=total,
        scam_count=scam_count,
        legitimate_count=legit_count,
        scam_percentage=scam_pct,
        recent_scans=recent_items[:5]
    )


@app.delete("/api/scans/clear-all", tags=["History"])
async def clear_all_user_history(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Clears all scan history records (both messages and audio scans) belonging to the authenticated user."""
    deleted_msgs = db.query(ScanRecord).filter(ScanRecord.user_id == user.id).delete()
    deleted_calls = db.query(CallScanRecord).filter(CallScanRecord.user_id == user.id).delete()
    db.commit()
    return {"status": "success", "message": f"Cleared {deleted_msgs + deleted_calls} scan records from history."}


@app.delete("/api/scans/{scan_id}", tags=["History"])
async def delete_scan_record(
    scan_id: int,
    record_type: Optional[str] = Query(None, pattern="^(message|call|url)$"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Deletes a specific scan record (message, call, or URL scan) belonging to the authenticated user."""
    if record_type == "call":
        rec = db.query(CallScanRecord).filter(CallScanRecord.id == scan_id, CallScanRecord.user_id == user.id).first()
        if not rec:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Call record not found or unauthorized.")
        db.delete(rec)
        db.commit()
        return {"status": "success", "message": f"Call scan record #{scan_id} deleted successfully."}
    elif record_type in ("message", "url"):
        rec = db.query(ScanRecord).filter(ScanRecord.id == scan_id, ScanRecord.user_id == user.id).first()
        if not rec:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan record not found or unauthorized.")
        db.delete(rec)
        db.commit()
        return {"status": "success", "message": f"Scan record #{scan_id} deleted successfully."}
    else:
        # Check ScanRecord first, then CallScanRecord
        rec = db.query(ScanRecord).filter(ScanRecord.id == scan_id, ScanRecord.user_id == user.id).first()
        if rec:
            db.delete(rec)
            db.commit()
            return {"status": "success", "message": f"Scan record #{scan_id} deleted successfully."}
        call_rec = db.query(CallScanRecord).filter(CallScanRecord.id == scan_id, CallScanRecord.user_id == user.id).first()
        if call_rec:
            db.delete(call_rec)
            db.commit()
            return {"status": "success", "message": f"Call scan record #{scan_id} deleted successfully."}
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Record not found or unauthorized.")


# =============================================================================
# PDF REPORT GENERATION ENDPOINTS
# =============================================================================

@app.get("/api/scans/{scan_id}/report.pdf", tags=["Reports"])
async def download_scan_pdf_by_id(
    scan_id: int,
    record_type: Optional[str] = Query(None, pattern="^(message|call)$"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Generates and downloads a cybersecurity audit PDF report for a saved message or call scan."""
    if record_type != "call":
        rec = db.query(ScanRecord).filter(ScanRecord.id == scan_id, ScanRecord.user_id == user.id).first()
        if rec:
            scan_dict = {
                "is_scam": rec.is_scam,
                "predicted_label": rec.predicted_label,
                "predicted_class": rec.predicted_class,
                "confidence": rec.confidence,
                "confidence_percentage": f"{round(rec.confidence * 100, 1)}%",
                "decision_margin": rec.decision_margin,
                "risk_level": rec.risk_level,
                "indicators_detected": rec.indicators_list,
                "text_preview": rec.message_text[:300],
                "character_count": len(rec.message_text)
            }
            pdf_bytes = generate_scan_pdf_report(
                scan_data=scan_dict,
                report_id=f"SCAN-{rec.id:06d}",
                user_name=user.full_name
            )
            filename = f"ScamShield_Report_{rec.id}.pdf"
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'}
            )

    call_rec = db.query(CallScanRecord).filter(CallScanRecord.id == scan_id, CallScanRecord.user_id == user.id).first()
    if call_rec:
        call_dict = {
            "audio_filename": call_rec.audio_filename,
            "duration_seconds": call_rec.duration_seconds,
            "transcript": call_rec.transcript,
            "translated_transcript": call_rec.translated_transcript,
            "detected_language": call_rec.detected_language,
            "language_name": call_rec.language_name,
            "is_scam": call_rec.is_scam,
            "predicted_class": call_rec.predicted_class,
            "confidence": call_rec.confidence,
            "confidence_percentage": f"{round(call_rec.confidence * 100, 1)}%",
            "risk_level": call_rec.risk_level,
            "indicators_detected": call_rec.indicators_list,
            "safety_recommendations": []
        }
        pdf_bytes = generate_call_pdf_report(
            call_data=call_dict,
            report_id=f"CALL-{call_rec.id:06d}",
            user_name=user.full_name
        )
        filename = f"ScamShield_CallAudit_{call_rec.id}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan record not found or unauthorized.")



@app.post("/api/report/download", tags=["Reports"])
async def download_custom_report(
    payload: Dict[str, Any],
    user: Optional[User] = Depends(get_optional_user)
):
    """Generates and downloads a cybersecurity audit PDF report on-the-fly for any analysis result."""
    user_name = user.full_name if user else "ScamShield Guest User"
    rep_id = f"SCAN-{abs(hash(payload.get('text_preview', ''))) % 1000000:06d}"

    pdf_bytes = generate_scan_pdf_report(
        scan_data=payload,
        report_id=rep_id,
        user_name=user_name
    )

    filename = f"ScamShield_Analysis_{rep_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


# =============================================================================
# CALLSCAM MULTILINGUAL AUDIO ENDPOINTS
# =============================================================================

@app.post("/api/callscam/analyze", response_model=CallScanResponse, tags=["CallScam"])
async def analyze_call_recording(
    file: UploadFile = File(...),
    language_hint: str = Form("auto"),
    transcript_hint: Optional[str] = Form(None),
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db)
):
    """
    Analyzes an uploaded call recording or microphone capture:
    - Normalizes and transcribes speech across English, Hindi, and Bengali.
    - Identifies language family and script.
    - Evaluates social engineering fraud patterns and LinearSVC hyperplane margin.
    - If authenticated, persists the scan to the user's call history.
    - Cleans up temporary audio files immediately after processing.
    """
    try:
        content = await file.read()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read audio file: {str(exc)}"
        )

    try:
        fmt = validate_audio_file(content, file.filename or "recording.wav")
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(ve))

    temp_id = str(uuid.uuid4())
    temp_dir = Path(tempfile.gettempdir())
    temp_path = temp_dir / f"scamshield_call_{temp_id}.wav"

    try:
        with open(temp_path, "wb") as f:
            f.write(content)

        result = analyze_call_audio(
            wav_path=str(temp_path),
            original_filename=file.filename or "recording.wav",
            language_hint=language_hint,
            transcript_hint=transcript_hint
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(ve))
    except Exception as exc:
        logger.error(f"CallScam analysis failed: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Call audio processing failed: {str(exc)}"
        )
    finally:
        if temp_path.exists():
            try:
                os.remove(temp_path)
            except Exception as e:
                logger.debug(f"Failed to remove temp audio file {temp_path}: {e}")

    call_id = None
    call_created_at = None
    if user is not None:
        call_rec = CallScanRecord(
            user_id=user.id,
            audio_filename=result["audio_filename"],
            detected_language=result["detected_language"],
            language_name=result["language_name"],
            transcript=result["transcript"],
            translated_transcript=result.get("translated_transcript"),
            is_scam=result["is_scam"],
            predicted_class=result["predicted_class"],
            risk_level=result["risk_level"],
            confidence=result["confidence"],
            indicators_json=json.dumps(result.get("indicators_detected", [])),
            duration_seconds=result.get("duration_seconds")
        )
        db.add(call_rec)
        db.commit()
        db.refresh(call_rec)
        call_id = call_rec.id
        call_created_at = call_rec.created_at

    result["id"] = call_id
    result["created_at"] = call_created_at or datetime.now(timezone.utc)
    return CallScanResponse(**result)



@app.get("/api/callscam/{call_id}/report.pdf", tags=["CallScam"])
async def download_call_report_by_id(
    call_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Downloads an official CallScam cybersecurity PDF audit report for an authenticated call scan."""
    rec = db.query(CallScanRecord).filter(CallScanRecord.id == call_id, CallScanRecord.user_id == user.id).first()
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Call recording audit record not found or unauthorized.")

    call_dict = {
        "audio_filename": rec.audio_filename,
        "duration_seconds": rec.duration_seconds,
        "transcript": rec.transcript,
        "translated_transcript": rec.translated_transcript,
        "detected_language": rec.detected_language,
        "language_name": rec.language_name,
        "is_scam": rec.is_scam,
        "predicted_class": rec.predicted_class,
        "confidence": rec.confidence,
        "confidence_percentage": f"{round(rec.confidence * 100, 1)}%",
        "risk_level": rec.risk_level,
        "indicators_detected": rec.indicators_list,
        "safety_recommendations": []
    }

    pdf_bytes = generate_call_pdf_report(
        call_data=call_dict,
        report_id=f"CALL-{rec.id:06d}",
        user_name=user.full_name
    )

    filename = f"ScamShield_CallAudit_{rec.id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.post("/api/callscam/report/download", tags=["CallScam"])
async def download_custom_call_report(
    payload: Dict[str, Any],
    user: Optional[User] = Depends(get_optional_user)
):
    """Generates and downloads a CallScam PDF audit report on-the-fly for guest or instant call analyses."""
    user_name = user.full_name if user else "ScamShield Guest User"
    rep_id = f"CALL-{abs(hash(payload.get('transcript', ''))) % 1000000:06d}"

    pdf_bytes = generate_call_pdf_report(
        call_data=payload,
        report_id=rep_id,
        user_name=user_name
    )

    filename = f"ScamShield_CallAudit_{rep_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.delete("/api/callscam/{call_id}", tags=["CallScam"])
async def delete_call_record(call_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Deletes a specific call scan record belonging to the authenticated user."""
    rec = db.query(CallScanRecord).filter(CallScanRecord.id == call_id, CallScanRecord.user_id == user.id).first()
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Call record not found or unauthorized.")

    db.delete(rec)
    db.commit()
    return {"status": "success", "message": f"Call scan record #{call_id} permanently deleted."}



# =============================================================================
# SYSTEM & MODEL INFO ENDPOINTS
# =============================================================================

@app.get("/health", response_model=HealthResponse, tags=["System"])
@app.get("/api/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Health check endpoint returning system status and model readiness."""
    service = get_model_service()
    if not service.is_loaded:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model is not loaded or initialization failed."
        )
    return HealthResponse(
        status="healthy",
        model_loaded=service.is_loaded,
        model_file=service.model_path.name,
        classifier=service.classifier_name,
        api_version=API_VERSION,
        project_title=PROJECT_TITLE
    )


@app.get("/model/info", response_model=ModelInfoResponse, tags=["Model Info"])
@app.get("/api/model/info", response_model=ModelInfoResponse, tags=["Model Info"])
async def model_info():
    """Returns architecture specifications, vocabulary dimensions, and training evaluation results."""
    service = get_model_service()
    if not service.is_loaded:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Model is not loaded.")
    return ModelInfoResponse(**service.get_model_info())


@app.get("/model/metrics", tags=["Model Info"])
@app.get("/api/model/metrics", tags=["Model Info"])
async def model_metrics():
    """Returns held-out test set performance metrics and cross-validation comparisons."""
    service = get_model_service()
    info = service.get_model_info()
    return {
        "selected_model": info.get("model_name"),
        "heldout_test_metrics": info.get("heldout_test_metrics"),
        "cross_validation_comparison": info.get("cross_validation_results")
    }


# =============================================================================
# STATIC FILE SERVING FOR FRONTEND WEB PAGES
# =============================================================================

# Explicit HTML page routes so clean URLs and file names work in browser
FRONTEND_PAGES = [
    "index.html",
    "login.html",
    "register.html",
    "analyze.html",
    "results.html",
    "dashboard.html",
    "history.html",
    "how-it-works.html",
    "model-performance.html",
    "about.html",
    "urlscan.html"
]


@app.get("/", response_class=FileResponse, tags=["Frontend"])
async def serve_home():
    home_file = BASE_DIR / "index.html"
    if home_file.exists():
        return FileResponse(home_file)
    from dashboard_html import DASHBOARD_HTML
    return HTMLResponse(content=DASHBOARD_HTML)


@app.get("/{file_path:path}", response_class=FileResponse, tags=["Frontend"])
async def serve_static_assets(file_path: str):
    target = BASE_DIR / file_path
    # Security: do not serve sensitive backend files, databases, or training datasets
    forbidden_suffixes = {".py", ".pkl", ".db", ".csv", ".ipynb", ".env", ".json"}
    if target.suffix.lower() in forbidden_suffixes or target.name.startswith("."):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    
    if target.is_file():
        return FileResponse(target)

    # Support clean URLs without .html extension (e.g. /analyze, /callscam, /results, /history, /dashboard)
    html_target = BASE_DIR / f"{file_path}.html"
    if html_target.is_file():
        return FileResponse(html_target)

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")


# Helper to check if port is available
def _port_is_free(host: str, port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


if __name__ == "__main__":
    import sys
    import uvicorn

    # In production (Render, Railway, Heroku, Docker), don't fail on socket probe and disable auto-reload
    if not IS_PRODUCTION and not _port_is_free(HOST, PORT):
        logger.error(
            f"Port {PORT} on {HOST} is already in use by another program. "
            f"Stop that program, or choose another port, e.g. in PowerShell:  "
            f'$env:PORT="8005"; python main.py'
        )
        sys.exit(1)

    reload_flag = not IS_PRODUCTION and os.getenv("RELOAD", "false").lower() == "true"
    logger.info(f"Starting Uvicorn server on http://{HOST}:{PORT} (reload={reload_flag}, prod={IS_PRODUCTION}) ...")
    uvicorn.run("main:app", host=HOST, port=PORT, reload=reload_flag)
