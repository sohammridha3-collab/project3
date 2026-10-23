"""
Machine Learning Model Service for Scam Detection
Handles pipeline loading, prediction execution, score calibration, and explainability cues.
"""

import os
import re
import time
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional

import numpy as np
import pandas as pd
import joblib

logger = logging.getLogger("scam_detector.model_service")

# Label mappings as established during model training
LABEL_NAMES = {
    0: "Legitimate / Ham",
    1: "Scam / Suspicious"
}

# Regex patterns for explainable scam heuristic indicators
INDICATOR_PATTERNS = {
    "Urgency / Threat": re.compile(
        r"\b(urgent|immediately|act now|account suspended|deactivated|within 24 hours|final notice|critical alert)\b",
        re.IGNORECASE
    ),
    "Financial / Prize Lure": re.compile(
        r"\b(winner|lottery|won|cash prize|\$\d+|claim your reward|free gift|million dollars|payout|bonus)\b",
        re.IGNORECASE
    ),
    "Credential Harvesting": re.compile(
        r"\b(verify your (account|password|identity|ssn|pin)|login now|reset password|security credentials)\b",
        re.IGNORECASE
    ),
    "Suspicious URL / Shortener": re.compile(
        r"(https?://\S+|bit\.ly/\S+|tinyurl\.com/\S+|goo\.gl/\S+|t\.co/\S+|ow\.ly/\S+|is\.gd/\S+|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)",
        re.IGNORECASE
    ),
    "Bank / Payment Impersonation": re.compile(
        r"\b(bank|paypal|crypto|bitcoin|wallet|credit card|wire transfer|western union|irs|tax refund)\b",
        re.IGNORECASE
    )
}


class ModelLoadError(Exception):
    """Raised when the ML model pipeline cannot be loaded or is invalid."""
    pass


class ScamDetectorService:
    """
    Singleton service managing the trained scikit-learn Pipeline.
    Loads the pipeline once on startup into memory.
    """
    _instance: Optional["ScamDetectorService"] = None

    def __init__(self, model_filename: Optional[str] = None):
        self.base_dir = Path(__file__).resolve().parent
        
        # Priority: explicit argument -> config.MODEL_PATH -> default file
        try:
            from config import MODEL_PATH, MODEL_DOWNLOAD_URL
            default_path = MODEL_PATH
            self.download_url = MODEL_DOWNLOAD_URL
        except ImportError:
            default_path = self.base_dir / (model_filename or "scam_detection_pipeline.pkl")
            self.download_url = os.getenv("MODEL_DOWNLOAD_URL") or os.getenv("MODEL_URL")

        if model_filename:
            p = Path(model_filename)
            self.model_path = p if p.is_absolute() else (self.base_dir / p)
        else:
            self.model_path = default_path

        self.metadata_path = self.base_dir / "model_metadata.json"
        self.metrics_path = self.base_dir / "heldout_test_metrics.csv"
        self.cv_path = self.base_dir / "cross_validation_comparison.csv"
        self.cm_path = self.base_dir / "confusion_matrix.csv"

        self.pipeline: Optional[Any] = None
        self.classifier_name: str = "Unknown"
        self.feature_step_names: List[str] = []
        self.is_loaded: bool = False
        self.load_timestamp: Optional[float] = None

    @classmethod
    def get_instance(cls, model_filename: Optional[str] = None) -> "ScamDetectorService":
        if cls._instance is None:
            cls._instance = cls(model_filename)
        return cls._instance

    def _download_model_artifact(self) -> None:
        """Downloads model artifact if missing locally and remote URL is configured."""
        if self.model_path.exists():
            return

        dl_url = self.download_url or os.getenv("MODEL_DOWNLOAD_URL") or os.getenv("MODEL_URL")
        if not dl_url:
            return

        logger.info(f"Model file not found locally. Initiating artifact download from {dl_url}...")
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        temp_file = self.model_path.with_suffix(".download.tmp")
        try:
            import urllib.request
            req = urllib.request.Request(
                dl_url,
                headers={"User-Agent": "ScamShieldAI-ModelFetcher/1.0"}
            )
            with urllib.request.urlopen(req, timeout=120) as resp, open(temp_file, "wb") as f_out:
                if resp.status not in (200, 206):
                    raise ModelLoadError(f"Model download failed with HTTP status {resp.status}")
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    f_out.write(chunk)

            size_bytes = temp_file.stat().st_size
            if size_bytes < 100000:
                raise ModelLoadError(f"Downloaded model artifact too small ({size_bytes} bytes). Check URL validity.")

            temp_file.replace(self.model_path)
            logger.info(f"✅ Downloaded model artifact successfully ({size_bytes} bytes) to {self.model_path}")
        except Exception as exc:
            if temp_file.exists():
                temp_file.unlink()
            raise ModelLoadError(f"Automatic model artifact download failed: {exc}") from exc

    def load_model(self) -> None:
        """
        Loads the pickled ML pipeline into memory.
        Validates pipeline structure to ensure it's compatible with prediction calls.
        """
        if not self.model_path.exists():
            self._download_model_artifact()

        if not self.model_path.exists():
            error_msg = (
                f"Model file not found at expected path: {self.model_path}. "
                "Ensure 'scam_detection_pipeline.pkl' is committed to the repository root, "
                "mounted via persistent volume (MODEL_PATH), or configure MODEL_DOWNLOAD_URL."
            )
            logger.critical(error_msg)
            raise ModelLoadError(error_msg)

        logger.info(f"Loading ML pipeline from: {self.model_path}...")
        start_time = time.time()

        try:
            self.pipeline = joblib.load(self.model_path)
        except Exception as exc:
            error_msg = f"Failed to deserialize model pipeline with joblib: {exc}"
            logger.critical(error_msg, exc_info=True)
            raise ModelLoadError(error_msg) from exc

        # Validate pipeline interface
        if not hasattr(self.pipeline, "predict"):
            raise ModelLoadError("Loaded object does not implement a 'predict' method.")

        # Inspect pipeline steps
        if hasattr(self.pipeline, "named_steps"):
            classifier = self.pipeline.named_steps.get("classifier")
            self.classifier_name = type(classifier).__name__ if classifier else "Pipeline Classifier"
            
            features = self.pipeline.named_steps.get("features")
            if features and hasattr(features, "transformer_list"):
                self.feature_step_names = [name for name, _ in features.transformer_list]
        else:
            self.classifier_name = type(self.pipeline).__name__

        self.is_loaded = True
        self.load_timestamp = time.time()
        elapsed = self.load_timestamp - start_time
        logger.info(
            f"Successfully loaded {self.classifier_name} pipeline in {elapsed:.3f}s. "
            f"Features: {self.feature_step_names}"
        )

    def predict_single(self, text: str) -> Dict[str, Any]:
        """
        Performs inference on a single text string using the pre-loaded pipeline.
        Calculates calibrated probability, decision margin, risk category, and heuristic cues.
        """
        if not self.is_loaded or self.pipeline is None:
            raise ModelLoadError("Model pipeline is not loaded. Cannot execute prediction.")

        cleaned_text = (text or "").strip()
        if not cleaned_text:
            raise ValueError("Input text cannot be empty or solely whitespace.")

        # Truncate text to safety bound consistent with Colab training (20,000 chars)
        eval_text = cleaned_text[:20000]

        # 1. Pipeline classification prediction (0 or 1)
        raw_pred = self.pipeline.predict([eval_text])[0]
        predicted_label = int(raw_pred)
        is_scam = bool(predicted_label == 1)

        # 2. Probability and margin calculation
        confidence: float = 0.5
        decision_margin: Optional[float] = None
        score_type: str = "calibrated_sigmoid"

        if hasattr(self.pipeline, "predict_proba"):
            proba = self.pipeline.predict_proba([eval_text])[0]
            confidence = float(proba[1])
            score_type = "predict_proba"
        elif hasattr(self.pipeline, "decision_function"):
            decision_val = float(np.ravel(self.pipeline.decision_function([eval_text]))[0])
            decision_margin = round(decision_val, 4)
            # Calibrated probability via standard Platt sigmoid: 1 / (1 + exp(-z))
            confidence = float(1.0 / (1.0 + np.exp(-decision_val)))
            score_type = "calibrated_sigmoid"
        else:
            confidence = 1.0 if is_scam else 0.0
            score_type = "binary_hard_assignment"

        # Bound confidence between 0.001 and 0.999 for numerical stability
        confidence = max(0.001, min(0.999, confidence))

        # 3. Categorize risk level
        if confidence >= 0.75:
            risk_level = "HIGH_RISK"
        elif confidence >= 0.50:
            risk_level = "SUSPICIOUS"
        elif confidence >= 0.25:
            risk_level = "LOW_RISK"
        else:
            risk_level = "SAFE_LEGITIMATE"

        # 4. Extract explainable heuristic indicators
        indicators = self._extract_indicators(eval_text)

        return {
            "is_scam": is_scam,
            "predicted_label": predicted_label,
            "predicted_class": LABEL_NAMES.get(predicted_label, f"Class {predicted_label}"),
            "confidence": round(confidence, 4),
            "confidence_percentage": f"{round(confidence * 100, 2)}%",
            "decision_margin": decision_margin,
            "risk_level": risk_level,
            "score_type": score_type,
            "indicators_detected": indicators,
            "text_preview": (eval_text[:117] + "...") if len(eval_text) > 120 else eval_text,
            "character_count": len(eval_text)
        }

    def predict_batch(self, texts: List[str]) -> Dict[str, Any]:
        """
        Performs batched inference across multiple text inputs.
        Optimized by passing the full list of strings to pipeline.predict in a single call.
        """
        if not self.is_loaded or self.pipeline is None:
            raise ModelLoadError("Model pipeline is not loaded. Cannot execute batch prediction.")

        start_time = time.time()
        processed_texts = [(t or "").strip()[:20000] for t in texts]

        # Fast vectorizer + classifier inference in one batch pass
        predictions = self.pipeline.predict(processed_texts)
        
        has_proba = hasattr(self.pipeline, "predict_proba")
        has_decision = hasattr(self.pipeline, "decision_function")
        
        if has_proba:
            probas = self.pipeline.predict_proba(processed_texts)[:, 1]
            margins = [None] * len(processed_texts)
            confidences = probas.tolist()
            score_type = "predict_proba"
        elif has_decision:
            raw_margins = np.ravel(self.pipeline.decision_function(processed_texts))
            margins = [round(float(m), 4) for m in raw_margins]
            confidences = (1.0 / (1.0 + np.exp(-raw_margins))).tolist()
            score_type = "calibrated_sigmoid"
        else:
            margins = [None] * len(processed_texts)
            confidences = [1.0 if p == 1 else 0.0 for p in predictions]
            score_type = "binary_hard_assignment"

        results = []
        scam_count = 0

        for idx, (text, pred, conf, margin) in enumerate(zip(processed_texts, predictions, confidences, margins)):
            label = int(pred)
            is_scam = (label == 1)
            if is_scam:
                scam_count += 1

            bounded_conf = max(0.001, min(0.999, float(conf)))
            
            if bounded_conf >= 0.75:
                risk_level = "HIGH_RISK"
            elif bounded_conf >= 0.50:
                risk_level = "SUSPICIOUS"
            elif bounded_conf >= 0.25:
                risk_level = "LOW_RISK"
            else:
                risk_level = "SAFE_LEGITIMATE"

            indicators = self._extract_indicators(text)

            results.append({
                "is_scam": is_scam,
                "predicted_label": label,
                "predicted_class": LABEL_NAMES.get(label, f"Class {label}"),
                "confidence": round(bounded_conf, 4),
                "confidence_percentage": f"{round(bounded_conf * 100, 2)}%",
                "decision_margin": margin,
                "risk_level": risk_level,
                "score_type": score_type,
                "indicators_detected": indicators,
                "text_preview": (text[:117] + "...") if len(text) > 120 else text,
                "character_count": len(text)
            })

        total = len(texts)
        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        scam_pct = round((scam_count / total * 100), 2) if total > 0 else 0.0

        return {
            "total_messages": total,
            "scam_count": scam_count,
            "legitimate_count": total - scam_count,
            "overall_scam_percentage": scam_pct,
            "processing_time_ms": elapsed_ms,
            "results": results
        }

    def get_model_info(self) -> Dict[str, Any]:
        """
        Returns architectural details and evaluation records of the model.
        """
        vocab_sizes: Dict[str, Any] = {}
        if self.pipeline and hasattr(self.pipeline, "named_steps"):
            features = self.pipeline.named_steps.get("features")
            if features and hasattr(features, "named_transformers"):
                for name, trans in features.named_transformers.items():
                    if hasattr(trans, "vocabulary_"):
                        vocab_sizes[name] = len(trans.vocabulary_)

        # Load metadata if present
        metadata = {}
        if self.metadata_path.exists():
            try:
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    metadata = json.load(f)
            except Exception as e:
                logger.warning(f"Could not read metadata file: {e}")

        # Load heldout test metrics if present
        heldout_metrics = None
        if self.metrics_path.exists():
            try:
                df_metrics = pd.read_csv(self.metrics_path)
                heldout_metrics = df_metrics.to_dict(orient="records")[0]
            except Exception as e:
                logger.warning(f"Could not read heldout test metrics: {e}")

        # Load CV comparisons if present
        cv_records = None
        if self.cv_path.exists():
            try:
                df_cv = pd.read_csv(self.cv_path)
                cv_records = df_cv.to_dict(orient="records")
            except Exception as e:
                logger.warning(f"Could not read cross validation comparison: {e}")

        return {
            "model_name": metadata.get("selected_model", self.classifier_name),
            "model_file": self.model_path.name,
            "classifier_type": self.classifier_name,
            "feature_extractors": self.feature_step_names,
            "vocabulary_sizes": vocab_sizes,
            "classes": [0, 1],
            "label_mapping": {
                "0": LABEL_NAMES[0],
                "1": LABEL_NAMES[1]
            },
            "training_dataset": metadata.get("training_dataset", "CEAS_08.csv"),
            "heldout_test_metrics": heldout_metrics,
            "cross_validation_results": cv_records
        }

    def _extract_indicators(self, text: str) -> List[str]:
        """Helper that scans text for common phishing and scam keyword triggers."""
        detected = []
        for category, pattern in INDICATOR_PATTERNS.items():
            if pattern.search(text):
                detected.append(category)
        return detected


# Module-level convenience singleton getter
def get_model_service() -> ScamDetectorService:
    return ScamDetectorService.get_instance()
