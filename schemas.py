"""
Pydantic Schemas for AI-Based Scam Message Detection API
Compatible with Pydantic v2 and FastAPI
"""

import re
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, ConfigDict, Field, model_validator, EmailStr, field_serializer


def serialize_utc_datetime(dt: Optional[datetime]) -> Optional[str]:
    """Serializes datetime object to unambiguous ISO 8601 UTC string with trailing 'Z'."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")



# =============================================================================
# INFERENCE SCHEMAS
# =============================================================================

class MessageInput(BaseModel):
    """
    Schema for single message prediction.
    Accepts raw text, or structured subject + body for emails.
    """
    text: Optional[str] = Field(
        default=None,
        description="The full message or SMS text to analyze.",
        examples=["URGENT: Your account has been compromised. Click here to verify your identity immediately: http://bit.ly/secure-login"]
    )
    message: Optional[str] = Field(
        default=None,
        description="Alternative field name for text (for flexible frontend integration)."
    )
    msg: Optional[str] = Field(
        default=None,
        description="Alternative short field name for text."
    )
    content: Optional[str] = Field(
        default=None,
        description="Alternative field name for content (for flexible frontend integration)."
    )
    subject: Optional[str] = Field(
        default=None,
        description="Optional email subject line. If provided with body, formatted for model compatibility.",
        examples=["Security Alert: Action Required"]
    )
    body: Optional[str] = Field(
        default=None,
        description="Optional email body text.",
        examples=["Your bank password will expire in 2 hours. Reset it now."]
    )
    message_type: Optional[str] = Field(
        default="auto",
        description="Message category hint: 'email', 'sms', or 'auto'.",
        examples=["email"]
    )

    @model_validator(mode="after")
    def validate_content_present(self) -> "MessageInput":
        """Ensure at least one text content source is provided and not empty."""
        has_text = any(
            isinstance(val, str) and val.strip()
            for val in [self.text, self.message, self.msg, self.content]
        )
        has_subject_or_body = any(
            isinstance(val, str) and val.strip()
            for val in [self.subject, self.body]
        )

        if not has_text and not has_subject_or_body:
            raise ValueError(
                "Message content cannot be empty. Please provide either 'text', 'message', "
                "or at least one of 'subject' / 'body'."
            )
        return self

    def get_processed_text(self, max_length: int = 20000) -> str:
        """
        Formats text into the exact representation expected by the trained pipeline.
        If subject and body are provided, formats as 'SUBJECT: <subject> BODY: <body>'.
        Otherwise uses the primary text field.
        """
        if self.subject is not None or self.body is not None:
            subj = (self.subject or "").strip()[:500]
            bdy = (self.body or "").strip()[:max_length]
            combined = f"SUBJECT: {subj} BODY: {bdy}".strip()
            return combined[:max_length]

        raw = self.text or self.message or self.msg or self.content or ""
        return raw.strip()[:max_length]


class BatchMessageInput(BaseModel):
    """
    Schema for batch message predictions.
    Supports up to 100 messages per request for high-throughput batch evaluation.
    """
    messages: List[MessageInput] = Field(
        ...,
        description="List of messages to classify.",
        min_length=1,
        max_length=100
    )


class PredictionResult(BaseModel):
    """
    Prediction result for an individual message.
    """
    scan_id: Optional[int] = Field(
        default=None,
        description="Database record ID if scan was saved to history."
    )
    is_scam: bool = Field(
        ...,
        description="True if the message is classified as scam/phishing/spam, False if legitimate."
    )
    predicted_label: int = Field(
        ...,
        description="Numerical class label: 1 for scam/suspicious, 0 for legitimate/ham."
    )
    predicted_class: str = Field(
        ...,
        description="Human-readable class name ('Scam / Suspicious' or 'Legitimate / Ham')."
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Calibrated probability score between 0.0 and 1.0 (higher = greater likelihood of scam)."
    )
    confidence_percentage: str = Field(
        ...,
        description="Formatted confidence percentage string (e.g., '94.5%')."
    )
    decision_margin: Optional[float] = Field(
        default=None,
        description="Raw decision boundary distance from LinearSVC (> 0 indicates scam class)."
    )
    risk_level: str = Field(
        ...,
        description="Categorical risk rating: 'HIGH_RISK', 'SUSPICIOUS', 'LOW_RISK', or 'SAFE_LEGITIMATE'."
    )
    score_type: str = Field(
        ...,
        description="Method used for computing score ('calibrated_sigmoid' or 'predict_proba')."
    )
    indicators_detected: List[str] = Field(
        default_factory=list,
        description="Heuristic cues identified in the message (urgency, suspicious links, lottery keywords, etc.)."
    )
    text_preview: str = Field(
        ...,
        description="First 120 characters of the analyzed message for reference."
    )
    character_count: int = Field(
        ...,
        description="Character count of evaluated text."
    )


class BatchPredictionResponse(BaseModel):
    """
    Response schema for batch message predictions.
    """
    total_messages: int = Field(..., description="Total number of messages processed in this batch.")
    scam_count: int = Field(..., description="Number of messages classified as scam.")
    legitimate_count: int = Field(..., description="Number of messages classified as legitimate.")
    overall_scam_percentage: float = Field(..., description="Percentage of messages flagged as scam.")
    processing_time_ms: float = Field(..., description="Total pipeline execution time in milliseconds.")
    results: List[PredictionResult] = Field(..., description="Detailed prediction results for each message.")


# =============================================================================
# AUTHENTICATION SCHEMAS
# =============================================================================

class UserRegister(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=120, examples=["Alex Morgan"])
    email: str = Field(..., examples=["alex@example.com"])
    password: str = Field(..., min_length=8, max_length=100, examples=["SecretPass123!"])
    confirm_password: str = Field(..., min_length=8, max_length=100, examples=["SecretPass123!"])

    @model_validator(mode="after")
    def validate_registration(self) -> "UserRegister":
        # Email format check
        email_pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        if not re.match(email_pattern, self.email):
            raise ValueError("Please provide a valid email address.")

        # Password match check
        if self.password != self.confirm_password:
            raise ValueError("Password confirmation does not match password.")

        # Basic password strength
        if not any(c.isupper() for c in self.password) or not any(c.isdigit() for c in self.password):
            raise ValueError("Password must contain at least one uppercase letter and one number.")

        return self


class UserLogin(BaseModel):
    email: str = Field(..., examples=["alex@example.com"])
    password: str = Field(..., examples=["SecretPass123!"])


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: int
    full_name: str
    email: str
    created_at: datetime

    @field_serializer("created_at")
    def serialize_datetime(self, dt: datetime, _info) -> str:
        return serialize_utc_datetime(dt) or ""


class TokenResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    access_token: str
    token_type: str = "bearer"
    user: UserResponse


# =============================================================================
# SCAN HISTORY SCHEMAS
# =============================================================================

class ScanRecordResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: int
    record_type: str = "message"  # "message" or "call"
    user_id: Optional[int] = None
    message_text: str
    subject: Optional[str] = None
    message_type: Optional[str] = "auto"
    predicted_label: int = 0
    predicted_class: str
    is_scam: bool
    confidence: float
    confidence_percentage: str
    decision_margin: Optional[float] = None
    risk_level: str
    indicators_detected: List[str] = Field(default_factory=list)
    created_at: datetime

    # Audio/CallScam specific fields
    audio_filename: Optional[str] = None
    detected_language: Optional[str] = None
    language_name: Optional[str] = None
    transcript: Optional[str] = None
    translated_transcript: Optional[str] = None
    duration_seconds: Optional[float] = None

    # URL Scanner specific fields
    url: Optional[str] = None
    normalized_url: Optional[str] = None

    @field_serializer("created_at")
    def serialize_datetime(self, dt: datetime, _info) -> str:
        return serialize_utc_datetime(dt) or ""



class ScanStatsResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    total_scans: int
    scam_count: int
    legitimate_count: int
    scam_percentage: float
    recent_scans: List[ScanRecordResponse] = Field(default_factory=list)


# =============================================================================
# SYSTEM & MODEL INFO SCHEMAS
# =============================================================================

class ModelInfoResponse(BaseModel):
    """
    Model metadata and architectural specifications.
    """
    model_config = ConfigDict(protected_namespaces=())

    model_name: str
    model_file: str
    classifier_type: str
    feature_extractors: List[str]
    vocabulary_sizes: Dict[str, Any]
    classes: List[int]
    label_mapping: Dict[str, str]
    training_dataset: str
    heldout_test_metrics: Optional[Dict[str, Any]] = None
    cross_validation_results: Optional[List[Dict[str, Any]]] = None


class HealthResponse(BaseModel):
    """
    Health check status response schema.
    """
    model_config = ConfigDict(protected_namespaces=())

    status: str = Field(..., examples=["healthy"])
    model_loaded: bool = Field(..., examples=[True])
    model_file: str = Field(..., examples=["scam_detection_pipeline.pkl"])
    classifier: str = Field(..., examples=["LinearSVC"])
    api_version: str = Field(..., examples=["1.0.0"])
    project_title: str = Field(..., examples=["AI-Based Scam Message Detection"])


# =============================================================================
# CALLSCAM SCHEMAS
# =============================================================================

class CallScanResponse(BaseModel):
    """
    Response schema for CallScam multilingual audio evaluation.
    """
    model_config = ConfigDict(protected_namespaces=())

    id: Optional[int] = None
    audio_filename: str
    duration_seconds: Optional[float] = None
    transcript: str
    translated_transcript: Optional[str] = None
    detected_language: str
    language_name: str
    is_scam: bool
    predicted_class: str
    confidence: float
    confidence_percentage: str
    risk_level: str
    decision_margin: Optional[float] = None
    indicators_detected: List[str] = Field(default_factory=list)
    safety_recommendations: List[str] = Field(default_factory=list)
    audio_status: str
    created_at: Optional[datetime] = None

    @field_serializer("created_at")
    def serialize_datetime(self, dt: Optional[datetime], _info) -> Optional[str]:
        return serialize_utc_datetime(dt)


# =============================================================================
# URL & WEBSITE SCANNER SCHEMAS
# =============================================================================

class UrlScanRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="Target website URL to inspect (supports http:// and https://).",
        examples=["https://example.com"]
    )


class UrlSecurityCheck(BaseModel):
    name: str = Field(..., description="Name of the security check.")
    category: str = Field(..., description="Category (Structure, Domain, Encryption, Network, Heuristics, Threat Intelligence).")
    status: str = Field(..., description="Result status: pass, warning, fail, unavailable, info.")
    description: str = Field(..., description="Brief explanation of the check.")
    details: Optional[str] = Field(default=None, description="Observed evidence or diagnostic details.")
    duration_ms: Optional[float] = Field(default=None, description="Execution time in milliseconds.")


class UrlScanResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    url: str = Field(..., description="Submitted raw URL.")
    normalized_url: str = Field(..., description="Safely normalized and parsed URL.")
    classification: str = Field(..., description="Risk verdict: Low Risk, Suspicious, High Risk, or Unknown.")
    risk_score: float = Field(..., description="Deterministic threat risk score between 0.0 and 100.0.")
    checks: List[UrlSecurityCheck] = Field(default_factory=list, description="Granular security check results.")
    findings: List[str] = Field(default_factory=list, description="Evidence supporting detected security warnings.")
    recommendations: List[str] = Field(default_factory=list, description="Recommended user defense actions.")
    scan_timestamp: datetime = Field(..., description="Timestamp when analysis was performed.")
    scan_id: Optional[int] = Field(default=None, description="Database record ID if scan was persisted.")
    domain_info: Optional[Dict[str, Any]] = Field(default=None, description="Domain and public suffix metadata.")
    https_info: Optional[Dict[str, Any]] = Field(default=None, description="TLS certificate and HTTPS metadata.")
    redirect_info: Optional[Dict[str, Any]] = Field(default=None, description="Redirect trace and final landing page.")
    threat_intel_info: Optional[Dict[str, Any]] = Field(default=None, description="Threat reputation provider status.")
    resolved_ip: Optional[str] = Field(default=None, description="Resolved public IP address.")
    scan_duration_ms: Optional[float] = Field(default=None, description="Total scan execution duration in milliseconds.")
    disclaimer: str = Field(
        default="Automated security checks evaluate observed technical indicators and heuristics. They cannot guarantee that a website is free from fraud, social engineering, or emerging threats.",
        description="Responsible disclosure disclaimer."
    )

    @field_serializer("scan_timestamp")
    def serialize_datetime(self, dt: datetime, _info) -> str:
        return serialize_utc_datetime(dt) or ""
