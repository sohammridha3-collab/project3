"""
SQLAlchemy Database Models for Users and Scan History
"""

import json
from datetime import datetime, timezone
from typing import List

from sqlalchemy import Column, Integer, String, Text, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    full_name = Column(String(120), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Scans performed by this user
    scans = relationship("ScanRecord", back_populates="user", cascade="all, delete-orphan", order_by="desc(ScanRecord.created_at)")
    call_scans = relationship("CallScanRecord", back_populates="user", cascade="all, delete-orphan", order_by="desc(CallScanRecord.created_at)")


class ScanRecord(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    
    # Message content
    message_text = Column(Text, nullable=False)
    subject = Column(String(500), nullable=True)
    message_type = Column(String(50), default="auto")

    # Classification output
    predicted_label = Column(Integer, nullable=False)
    predicted_class = Column(String(50), nullable=False)
    is_scam = Column(Boolean, nullable=False)
    confidence = Column(Float, nullable=False)
    decision_margin = Column(Float, nullable=True)
    risk_level = Column(String(50), nullable=False)
    
    # Heuristic indicators stored as JSON array string
    indicators_json = Column(Text, default="[]")
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    user = relationship("User", back_populates="scans")

    @property
    def indicators_list(self) -> List[str]:
        try:
            return json.loads(self.indicators_json or "[]")
        except Exception:
            return []


class CallScanRecord(Base):
    __tablename__ = "call_scans"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)

    audio_filename = Column(String(255), nullable=True)
    detected_language = Column(String(50), nullable=False, default="en")
    language_name = Column(String(50), nullable=False, default="English")
    transcript = Column(Text, nullable=False)
    translated_transcript = Column(Text, nullable=True)

    is_scam = Column(Boolean, nullable=False, default=False)
    predicted_class = Column(String(50), nullable=False, default="Not Flagged as Scam")
    risk_level = Column(String(50), nullable=False, default="LOW_RISK")
    confidence = Column(Float, nullable=False, default=0.5)

    indicators_json = Column(Text, default="[]")
    duration_seconds = Column(Float, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    user = relationship("User", back_populates="call_scans")

    @property
    def indicators_list(self) -> List[str]:
        try:
            return json.loads(self.indicators_json or "[]")
        except Exception:
            return []

