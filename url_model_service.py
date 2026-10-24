"""
ScamShield AI — Phishing URL Classifier Service
Loads the trained HistGradientBoosting pipeline and runs ultra-fast (<1ms),
in-memory ML phishing probability estimation.
"""

import os
import time
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

import joblib
import pandas as pd

from url_features import (
    extract_url_features,
    NUMERIC_FEATURES,
    CATEGORICAL_FEATURES,
    FEATURE_COLUMNS
)

logger = logging.getLogger("scamshield.url_model_service")


class UrlClassifierService:
    """
    Singleton service managing the trained URL Phishing detection pipeline.
    Loads the pipeline once on startup into memory.
    """
    _instance: Optional["UrlClassifierService"] = None

    def __init__(self, model_filename: Optional[str] = None):
        self.base_dir = Path(__file__).resolve().parent
        
        # Priority: explicit argument -> models/ directory -> root directory
        candidate_paths = [
            self.base_dir / "models" / (model_filename or "url_classifier_pipeline.joblib"),
            self.base_dir / (model_filename or "url_classifier_pipeline.joblib")
        ]
        self.model_path = next((p for p in candidate_paths if p.exists()), candidate_paths[0])
        
        candidate_meta = [
            self.base_dir / "models" / "url_model_metadata.json",
            self.base_dir / "url_model_metadata.json"
        ]
        self.metadata_path = next((p for p in candidate_meta if p.exists()), candidate_meta[0])

        self.pipeline: Optional[Any] = None
        self.metadata: Dict[str, Any] = {}
        self.classifier_name: str = "Unknown"
        self.top_tlds_vocab: List[str] = []
        self.is_loaded: bool = False
        self.load_timestamp: Optional[float] = None

    @classmethod
    def get_instance(cls, model_filename: Optional[str] = None) -> "UrlClassifierService":
        if cls._instance is None:
            cls._instance = cls(model_filename)
        return cls._instance

    def load_model(self) -> None:
        """Loads model pipeline and metadata from disk into memory."""
        if self.is_loaded and self.pipeline is not None:
            return

        # Attempt to load metadata
        if self.metadata_path.exists():
            try:
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
                    self.classifier_name = self.metadata.get("selected_classifier", "HistGradientBoosting (Balanced)")
                    self.top_tlds_vocab = self.metadata.get("feature_schema", {}).get("top_tlds_vocabulary", [])
            except Exception as e:
                logger.warning(f"Could not load URL model metadata from {self.metadata_path}: {e}")

        # Attempt to load pipeline artifact
        if not self.model_path.exists():
            # Check if root has it
            root_cand = self.base_dir / "url_classifier_pipeline.joblib"
            if root_cand.exists():
                self.model_path = root_cand

        if not self.model_path.exists():
            logger.error(f"URL Classifier model artifact not found at {self.model_path}")
            self.is_loaded = False
            return

        try:
            t0 = time.perf_counter()
            self.pipeline = joblib.load(self.model_path)
            self.is_loaded = True
            self.load_timestamp = time.time()
            elapsed_ms = (time.perf_counter() - t0) * 1000
            logger.info(f"✅ Loaded URL Classifier pipeline '{self.classifier_name}' from {self.model_path.name} in {elapsed_ms:.1f}ms")
        except Exception as exc:
            self.is_loaded = False
            logger.error(f"❌ Failed to load URL Classifier pipeline from {self.model_path}: {exc}", exc_info=True)
            raise exc

    def predict_url(self, raw_url: str) -> Dict[str, Any]:
        """
        Runs instant in-memory ML inference on a URL string.
        Returns:
            Dict containing predicted_label, predicted_class, phishing_probability,
            confidence_percentage, explainable feature indicators, and execution duration.
        """
        if not self.is_loaded or self.pipeline is None:
            try:
                self.load_model()
            except Exception:
                pass

        if not self.is_loaded or self.pipeline is None:
            return {
                "available": False,
                "error": "ML URL classifier pipeline is not loaded.",
                "is_phishing": False,
                "phishing_probability": 0.0,
                "predicted_label": 0,
                "predicted_class": "Unavailable",
                "confidence": 0.0,
                "confidence_percentage": "0.0%",
                "model_name": self.classifier_name,
                "features": {},
                "duration_ms": 0.0
            }

        t_start = time.perf_counter()
        
        # 1. Extract canonical features
        raw_features = extract_url_features(raw_url)
        
        # 2. Map TLD to top vocabulary
        tld_val = raw_features.get("tld", "unknown")
        if self.top_tlds_vocab:
            tld_top = tld_val if tld_val in self.top_tlds_vocab else "other"
        else:
            tld_top = tld_val
        
        # 3. Create DataFrame matching Pipeline input schema
        row_dict = {k: raw_features[k] for k in NUMERIC_FEATURES}
        row_dict["tld_top"] = tld_top
        input_df = pd.DataFrame([row_dict])

        # 4. Predict probability and label
        try:
            if hasattr(self.pipeline, "predict_proba"):
                probs = self.pipeline.predict_proba(input_df)[0]
                phish_prob = float(probs[1])
                pred_label = 1 if phish_prob >= 0.5 else 0
            else:
                pred_label = int(self.pipeline.predict(input_df)[0])
                # Calibrate margin
                margin = float(self.pipeline.decision_function(input_df)[0])
                phish_prob = 1.0 / (1.0 + (2.718281828459045 ** (-margin)))

            confidence = phish_prob if pred_label == 1 else (1.0 - phish_prob)
            is_phishing = pred_label == 1
            predicted_class = "Phishing" if is_phishing else "Benign"

        except Exception as exc:
            logger.error(f"Prediction failed for URL '{raw_url}': {exc}", exc_info=True)
            return {
                "available": False,
                "error": f"Inference execution failed: {str(exc)}",
                "is_phishing": False,
                "phishing_probability": 0.0,
                "predicted_label": 0,
                "predicted_class": "Error",
                "confidence": 0.0,
                "confidence_percentage": "0.0%",
                "model_name": self.classifier_name,
                "features": raw_features,
                "duration_ms": round((time.perf_counter() - t_start) * 1000, 2)
            }

        duration_ms = round((time.perf_counter() - t_start) * 1000, 2)

        return {
            "available": True,
            "error": None,
            "is_phishing": is_phishing,
            "phishing_probability": round(phish_prob, 4),
            "predicted_label": pred_label,
            "predicted_class": predicted_class,
            "confidence": round(confidence, 4),
            "confidence_percentage": f"{round(confidence * 100, 1)}%",
            "model_name": self.classifier_name,
            "features": raw_features,
            "duration_ms": duration_ms
        }

    def get_info(self) -> Dict[str, Any]:
        """Returns model specifications, training metadata, and performance metrics."""
        return {
            "is_loaded": self.is_loaded,
            "classifier_name": self.classifier_name,
            "artifact_file": self.model_path.name if self.model_path else "None",
            "metadata": self.metadata
        }


def get_url_model_service() -> UrlClassifierService:
    """Returns singleton instance of UrlClassifierService."""
    return UrlClassifierService.get_instance()
