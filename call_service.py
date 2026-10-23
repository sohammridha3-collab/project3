"""
ScamShield AI — CallScam Multilingual Audio Analysis Engine
Handles audio validation, speech transcription (English, Hindi, Bengali),
script/language detection, and cross-lingual fraud classification.
"""

import os
import re
import wave
import logging
from typing import Dict, Any, List, Optional, Tuple

import numpy as np
import speech_recognition as sr
from model_service import get_model_service

logger = logging.getLogger("scamshield.call_service")

# Supported Languages Configuration
SUPPORTED_LANGUAGES = {
    "en": {"code": "en-US", "name": "English"},
    "hi": {"code": "hi-IN", "name": "Hindi (हिन्दी)"},
    "bn": {"code": "bn-IN", "name": "Bengali (বাংলা)"}
}

# Maximum audio upload size (25 MB)
MAX_AUDIO_BYTES = 25 * 1024 * 1024

# Supported Audio Extensions
ALLOWED_AUDIO_EXTENSIONS = {".wav", ".mp3", ".m4a", ".webm", ".ogg"}

# =============================================================================
# MULTILINGUAL FRAUD PATTERNS (English, Hindi, Bengali)
# =============================================================================

FRAUD_PATTERNS = {
    "hi": {
        "urgency_threats": [
            r"तुरंत", r"जल्दी", r"24\s*घंटे", r"पुलिस", r"गिरफ्तार", r"सीबीआई",
            r"जेल", r"वारंट", r"कोर्ट", r"अदालत", r"जुर्माना", r"ब्लॉक\s*हो\s*जाएगा",
            r"बंद\s*हो\s*जाएगा", r"निलंबित", r"कानूनी\s*कार्रवाई"
        ],
        "credentials_banking": [
            r"बैंक\s*खाता", r"एटीएम", r"डेबिट\s*कार्ड", r"क्रेडिट\s*कार्ड", r"पासवर्ड",
            r"ओटीपी", r"पिन\s*नंबर", r"सीवीवी", r"आधार\s*कार्ड", r"पैन\s*कार्ड",
            r"केवाईसी", r"बायोमेट्रिक", r"वेरिफाई\s*करें", r"खाता\s*सत्यापन"
        ],
        "financial_lures": [
            r"लॉटरी", r"इनाम", r"करोड़पति", r"कैशबैक", r"प्राइज", r"लकी\s*ड्रॉ",
            r"रिफंड", r"बोनस", r"घर\s*बैठे\s*कमाएं", r"नौकरी", r"पार्ट\s*टाइम"
        ],
        "remote_access": [
            r"एनीडेस्क", r"टीमव्यूअर", r"क्विक\s*सपोर्ट", r"स्क्रीन\s*शेयर", r"ऐप\s*डाउनलोड"
        ]
    },
    "bn": {
        "urgency_threats": [
            r"জরুরি", r"অবিলম্বে", r"২৪\s*ঘণ্টার\s*মধ্যে", r"পুলিশ", r"গ্রেপ্তার", r"সিবিআই",
            r"জেল", r"ওয়ারেন্ট", r"আইনি\s*ব্যবস্থা", r"জরিমানা", r"ব্লক\s*হবে",
            r"স্থগিত", r"বন্ধ\s*হয়ে\s*যাবে", r"বিদ্যুৎ\s*বিচ্ছিন্ন"
        ],
        "credentials_banking": [
            r"ব্যাংক\s*অ্যাকাউন্ট", r"এটিএম", r"ডেবিট\s*কার্ড", r"ক্রেডিট\s*কার্ড", r"পাসওয়ার্ড",
            r"ওটিপি", r"পিন\s*নম্বর", r"সিভিভি", r"আধার\s*কার্ড", r"প্যান\s*কার্ড",
            r"কেওয়াইসি", r"বায়োমেট্রিক", r"ভেরিফাই\s*করুন", r"অ্যাকাউন্ট\s*যাচাই"
        ],
        "financial_lures": [
            r"লটারি", r"পুরস্কার", r"কোটিপতি", r"ক্যাশব্যাক", r"প্রাইজ", r"লাকি\s*ড্র",
            r"রিফান্ড", r"বোনাস", r"ঘরে\s*বসে\s*আয়", r"চাকরি", r"পার্ট\s*টাইম"
        ],
        "remote_access": [
            r"এনিডেস্ক", r"টিমভিউয়ার", r"কুইক\s*সাপোর্ট", r"স্ক্রিন\s*শেয়ার", r"অ্যাপ\s*ডাউনলোড"
        ]
    },
    "en": {
        "urgency_threats": [
            r"\burgent\b", r"\bimmediately\b", r"\bwithin\s*24\s*hours\b", r"\barrest\b",
            r"\bpolice\b", r"\bfbi\b", r"\bcbi\b", r"\blawsuit\b", r"\bwarrant\b",
            r"\baccount\s*suspended\b", r"\baccount\s*locked\b", r"\bfrozen\b", r"\bpenalty\b"
        ],
        "credentials_banking": [
            r"\bbank\s*account\b", r"\bdebit\s*card\b", r"\bcredit\s*card\b", r"\bpassword\b",
            r"\botp\b", r"\bone[\s-]*time\s*password\b", r"\bpin\b", r"\bcvv\b",
            r"\bssn\b", r"\bsocial\s*security\b", r"\bkyc\s*update\b", r"\bverify\s*identity\b"
        ],
        "financial_lures": [
            r"\blottery\b", r"\bprize\b", r"\bwinner\b", r"\bcash\s*reward\b",
            r"\brefund\b", r"\bbonus\b", r"\bwork\s*from\s*home\b", r"\bcrypto\b", r"\bwire\s*transfer\b"
        ],
        "remote_access": [
            r"\banydesk\b", r"\bteamviewer\b", r"\bquicksupport\b", r"\bscreen\s*share\b", r"\binstall\s*app\b"
        ]
    }
}


def detect_script_language(text: str) -> Tuple[str, str]:
    """
    Identifies language family based on Unicode script distribution.
    Devanagari: \u0900 - \u097F -> Hindi
    Bengali: \u0980 - \u09FF -> Bengali
    Default / Latin: en -> English
    """
    if not text or not text.strip():
        return "en", "English"

    devanagari_count = len(re.findall(r"[\u0900-\u097F]", text))
    bengali_count = len(re.findall(r"[\u0980-\u09FF]", text))
    latin_count = len(re.findall(r"[a-zA-Z]", text))

    total = devanagari_count + bengali_count + latin_count
    if total == 0:
        return "en", "English"

    if devanagari_count / total > 0.3:
        return "hi", "Hindi (हिन्दी)"
    if bengali_count / total > 0.3:
        return "bn", "Bengali (বাংলা)"

    return "en", "English"


def validate_audio_file(file_bytes: bytes, filename: str) -> str:
    """
    Validates audio file size and checks magic header signatures.
    Raises ValueError on violation. Returns normalized format string.
    """
    if len(file_bytes) == 0:
        raise ValueError("Audio file is empty. Please provide a valid recording.")

    if len(file_bytes) > MAX_AUDIO_BYTES:
        mb_size = round(len(file_bytes) / (1024 * 1024), 2)
        raise ValueError(f"Audio file size ({mb_size} MB) exceeds maximum allowed limit of 25 MB.")

    _, ext = os.path.splitext(filename.lower())
    if ext not in ALLOWED_AUDIO_EXTENSIONS:
        raise ValueError(f"Unsupported audio format '{ext}'. Supported formats: WAV, MP3, M4A, WebM, OGG.")

    # Check magic bytes
    if file_bytes.startswith(b"RIFF") and b"WAVE" in file_bytes[:16]:
        return "wav"
    if file_bytes.startswith(b"ID3") or file_bytes[:2] == b"\xff\xfb" or file_bytes[:2] == b"\xff\xf3":
        return "mp3"
    if file_bytes.startswith(b"\x1a\x45\xdf\xa3"):
        return "webm"
    if b"ftypM4A" in file_bytes[:16] or b"ftypmp4" in file_bytes[:16]:
        return "m4a"

    # Allow if extension matches even if loose container
    return ext.lstrip(".")


def get_wav_duration_seconds(file_path: str) -> Optional[float]:
    """Inspects standard WAV file header to extract duration in seconds."""
    try:
        with wave.open(file_path, "rb") as wf:
            frames = wf.getnframes()
            rate = wf.getframerate()
            if rate > 0:
                return round(frames / float(rate), 2)
    except Exception as exc:
        logger.debug(f"Could not compute WAV duration: {exc}")
    return None


def boost_and_normalize_wav(wav_path: str, target_peak: int = 28000, max_gain: float = 15.0) -> float:
    """
    Amplifies and normalizes low-volume speech and call recordings so STT can accurately detect words.
    Returns the gain factor applied.
    """
    try:
        with wave.open(wav_path, "rb") as wf:
            params = wf.getparams()
            sampwidth = params.sampwidth
            n_frames = params.nframes
            raw_bytes = wf.readframes(n_frames)

        if sampwidth == 2 and n_frames > 0:  # 16-bit PCM
            data = np.frombuffer(raw_bytes, dtype=np.int16)
            if len(data) == 0:
                return 1.0

            max_val = int(np.max(np.abs(data)))
            # If the recording is quiet but contains sound (peak > 40)
            if 40 < max_val < target_peak:
                gain = min(target_peak / float(max_val), max_gain)
                if gain > 1.08:
                    boosted = np.clip(data.astype(np.float32) * gain, -32768, 32767).astype(np.int16)
                    with wave.open(wav_path, "wb") as wf:
                        wf.setparams(params)
                        wf.writeframes(boosted.tobytes())
                    logger.info(f"Boosted quiet audio by {gain:.2f}x (peak {max_val} -> {target_peak})")
                    return gain
    except Exception as exc:
        logger.warning(f"Audio volume boost warning: {exc}")
    return 1.0


def transcribe_audio_file(wav_path: str, language_hint: str = "auto") -> Tuple[str, str, str]:
    """
    Transcribes audio using SpeechRecognition with automatic or requested language routing.
    Includes adaptive low-volume audio amplification and multi-language fallbacks.
    Returns: (transcript_text, detected_lang_code, language_name)
    """
    # 1. Pre-amplify quiet audio if needed
    boost_and_normalize_wav(wav_path)

    recognizer = sr.Recognizer()
    recognizer.energy_threshold = 120
    recognizer.dynamic_energy_threshold = True
    recognizer.dynamic_energy_adjustment_damping = 0.15
    recognizer.dynamic_energy_ratio = 1.5

    try:
        with sr.AudioFile(wav_path) as source:
            audio_data = recognizer.record(source)
    except Exception as exc:
        raise ValueError(f"Audio format decoding error: {str(exc)}. Ensure the file is uncorrupted PCM WAV.")

    # Candidate languages with Indian English (en-IN) priority
    if language_hint == "hi":
        languages_to_try = ["hi-IN", "en-IN", "en-US"]
    elif language_hint == "bn":
        languages_to_try = ["bn-IN", "en-IN", "en-US"]
    elif language_hint == "en":
        languages_to_try = ["en-IN", "en-US", "hi-IN"]
    else:
        # Default auto order: en-IN, en-US, hi-IN, bn-IN
        languages_to_try = ["en-IN", "en-US", "hi-IN", "bn-IN"]

    transcript = ""
    used_lang_code = "en"
    used_lang_name = "English"

    last_error = None
    for lang in languages_to_try:
        try:
            candidate = recognizer.recognize_google(audio_data, language=lang)
            if candidate and candidate.strip():
                transcript = candidate.strip()
                # Determine language from script of the result
                det_code, det_name = detect_script_language(transcript)
                if language_hint in ("hi", "bn"):
                    used_lang_code = language_hint
                    used_lang_name = SUPPORTED_LANGUAGES[language_hint]["name"]
                else:
                    used_lang_code = det_code
                    used_lang_name = det_name
                break
        except sr.UnknownValueError:
            continue
        except sr.RequestError as req_err:
            last_error = req_err
            break
        except Exception as e:
            last_error = e

    if not transcript:
        if last_error:
            logger.warning(f"Speech recognition network request failed: {last_error}")
        return "", used_lang_code, used_lang_name

    return transcript, used_lang_code, used_lang_name


def scan_multilingual_indicators(text: str, lang_code: str) -> List[str]:
    """Scans text for explainable fraud and social engineering indicators."""
    indicators = []
    text_lower = text.lower()

    # Get patterns for target language + English fallback patterns
    lang_patterns = FRAUD_PATTERNS.get(lang_code, FRAUD_PATTERNS["en"])

    for category, regex_list in lang_patterns.items():
        matched = False
        for pat in regex_list:
            if re.search(pat, text_lower, re.IGNORECASE):
                matched = True
                break

        if matched:
            if category == "urgency_threats":
                indicators.append("Urgent Coercion / Legal Threat")
            elif category == "credentials_banking":
                indicators.append("Sensitive Credential / OTP Request")
            elif category == "financial_lures":
                indicators.append("Unrealistic Financial / Prize Lure")
            elif category == "remote_access":
                indicators.append("Remote Access Software Demand")

    # If non-English, also cross-check English patterns for code-switching
    if lang_code != "en":
        for category, regex_list in FRAUD_PATTERNS["en"].items():
            matched = False
            for pat in regex_list:
                if re.search(pat, text_lower, re.IGNORECASE):
                    matched = True
                    break
            if matched:
                tag = ""
                if category == "urgency_threats":
                    tag = "Urgent Coercion / Legal Threat"
                elif category == "credentials_banking":
                    tag = "Sensitive Credential / OTP Request"
                elif category == "financial_lures":
                    tag = "Unrealistic Financial / Prize Lure"
                elif category == "remote_access":
                    tag = "Remote Access Software Demand"
                if tag and tag not in indicators:
                    indicators.append(tag)

    return indicators


def translate_transcript_to_english(text: str, source_lang: str) -> Optional[str]:
    """
    Translates non-English transcript to English for ML pipeline evaluation.
    Falls back gracefully if external translation service is rate-limited.
    """
    if source_lang == "en" or not text.strip():
        return text

    try:
        from deep_translator import GoogleTranslator
        translated = GoogleTranslator(source=source_lang, target="en").translate(text)
        if translated and translated.strip():
            return translated.strip()
    except Exception as exc:
        logger.debug(f"Direct translation unavailable ({exc}); using native script heuristic evaluation.")
    return None


def get_localized_safety_recommendations(is_scam: bool, lang_code: str) -> List[str]:
    """Returns practical cybersecurity safety recommendations in the appropriate language."""
    if lang_code == "hi":
        if is_scam:
            return [
                "🚨 किसी भी व्यक्ति को अपना बैंक ओटीपी, पासवर्ड या यूपीआई पिन कभी न बताएं।",
                "📞 यदि कॉलर ने बैंक खाता या सिम ब्लॉक करने की धमकी दी है, तो तुरंत फोन काटें और आधिकारिक बैंक शाखा से संपर्क करें।",
                "🛑 कॉलर के कहने पर एनीडेस्क, टीमव्यूअर या कोई अज्ञात ऐप फोन में इंस्टॉल न करें।",
                "⚖️ इस संदिग्ध नंबर की शिकायत तुरंत राष्ट्रीय साइबर अपराध पोर्टल (cybercrime.gov.in) पर करें।"
            ]
        else:
            return [
                "✅ इस कॉल में किसी ज्ञात धोखाधड़ी के संकेत नहीं मिले हैं।",
                "⚠️ फिर भी, यदि कॉलर वित्तीय जानकारी या ओटीपी मांगे, तो सतर्क रहें।",
                "🔍 सांख्यिकीय एआई सिस्टम 100% सुरक्षा की पूर्ण गारंटी नहीं दे सकता।"
            ]
    elif lang_code == "bn":
        if is_scam:
            return [
                "🚨 ফোনে কাউকে কখনো আপনার ব্যাংক ওটিপি, পাসওয়ার্ড বা পিন নম্বর বলবেন না।",
                "📞 ব্যাংক অ্যাকাউন্ট বা বিদ্যুৎ সংযোগ কাটার হুমকি দিলে ফোন কেটে সরাসরি অফিশিয়াল হেল্পলাইনে ফোন করুন।",
                "🛑 কলারের নির্দেশে অ্যানিডেস্ক, টিমভিউয়ার বা কোনো অজানা অ্যাপ মোবাইলে ইনস্টল করবেন না।",
                "⚖️ সন্দেহজনক কলটির বিরুদ্ধে নিকটস্থ সাইবার ক্রাইম থানায় অভিযোগ দায়ের করুন।"
            ]
        else:
            return [
                "✅ এই রেকর্ডিংয়ে কোনো পরিচিত প্রতারণামূলক বার্তা বা হুমকির প্যাটার্ন ধরা পড়েনি।",
                "⚠️ সাধারণ সাইবার নিরাপত্তা বজায় রাখুন: অপ্রত্যাশিত আর্থিক লেনদেনের অনুরোধে সতর্ক থাকুন।",
                "🔍 কোনো এআই মডেলই শূন্য ঝুঁকির ১০০% নিশ্চয়তা প্রদান করতে পারে না।"
            ]
    else:
        if is_scam:
            return [
                "🚨 Never disclose banking OTPs, account passwords, or card PINs over the phone.",
                "📞 If the caller demanded immediate payment or threatened arrest, hang up and verify via official contacts.",
                "🛑 Do not install remote assistance applications (AnyDesk, TeamViewer) at the caller's request.",
                "⚖️ Report this fraudulent phone number immediately to your telecom provider or national cyber-crime unit."
            ]
        else:
            return [
                "✅ The recorded speech does not match known scam or social-engineering speech profiles.",
                "⚠️ Maintain zero-trust awareness: always confirm sender/caller claims via a secondary channel.",
                "🔍 Statistical machine learning cannot guarantee complete immunity against novel deception."
            ]


def analyze_call_audio(
    wav_path: str,
    original_filename: str,
    language_hint: str = "auto",
    transcript_hint: Optional[str] = None
) -> Dict[str, Any]:
    """
    Full end-to-end CallScam audio analysis:
    1. Transcribes speech in English, Hindi, or Bengali.
    2. Identifies language and script.
    3. Evaluates fraud indicators.
    4. Evaluates through LinearSVC pipeline.
    5. Returns unified threat analysis report.
    """
    # Duration
    duration = get_wav_duration_seconds(wav_path)

    # 1. Transcribe speech
    transcript, lang_code, lang_name = transcribe_audio_file(wav_path, language_hint)

    # Fallback to transcript_hint if STT didn't recognize speech (e.g. preset tone sample or low audio)
    if not transcript or not transcript.strip():
        if transcript_hint and transcript_hint.strip():
            transcript = transcript_hint.strip()
            det_code, det_name = detect_script_language(transcript)
            lang_code = language_hint if language_hint in ("hi", "bn", "en") else det_code
            lang_name = SUPPORTED_LANGUAGES.get(lang_code, {}).get("name", det_name)

    # If still no speech detected, return an Inconclusive assessment
    if not transcript or not transcript.strip():
        used_lang = language_hint if language_hint in ("hi", "bn", "en") else "en"
        used_name = SUPPORTED_LANGUAGES.get(used_lang, {}).get("name", "English")
        return {
            "audio_filename": original_filename,
            "duration_seconds": duration,
            "transcript": "[No clear speech detected in recording]",
            "translated_transcript": None,
            "detected_language": used_lang,
            "language_name": used_name,
            "is_scam": False,
            "predicted_class": "Inconclusive / No Clear Speech Detected",
            "confidence": 0.0,
            "confidence_percentage": "0.0%",
            "risk_level": "INCONCLUSIVE",
            "decision_margin": None,
            "indicators_detected": ["Speech Unintelligible or Low Volume"],
            "safety_recommendations": [
                "The speech-to-text system could not identify intelligible speech words in this audio.",
                "If recording via microphone, ensure microphone permissions are granted and speak clearly.",
                "Always verify unexpected communications directly via verified official channels."
            ],
            "audio_status": "Inconclusive (No Speech Detected)"
        }

    # 2. Extract heuristic warning indicators
    indicators = scan_multilingual_indicators(transcript, lang_code)

    # 3. Model Classification
    model_service = get_model_service()
    eval_text = transcript

    translated_text = None
    if lang_code in ("hi", "bn"):
        translated_text = translate_transcript_to_english(transcript, lang_code)
        if translated_text:
            eval_text = translated_text

    ml_result = None
    if model_service.is_loaded:
        try:
            ml_result = model_service.predict_single(eval_text)
        except Exception as exc:
            logger.warning(f"LinearSVC evaluation for call transcript failed: {exc}")

    # 4. Synthesize Defensible Threat Verdict
    # High-confidence indicators + ML margin
    has_critical_indicators = len(indicators) >= 1
    ml_flagged = bool(ml_result and ml_result.get("is_scam", False))

    is_scam = has_critical_indicators or ml_flagged
    confidence = ml_result["confidence"] if ml_result else (0.85 if has_critical_indicators else 0.15)

    if is_scam:
        risk_level = "HIGH_RISK" if len(indicators) >= 2 else "MEDIUM_RISK"
        predicted_class = "Potential Scam"
    else:
        risk_level = "LOW_RISK"
        predicted_class = "Not Flagged as Scam"

    # Confidence percentage string
    confidence_pct = f"{round(confidence * 100, 1)}%"

    # 5. Localized recommendations
    recommendations = get_localized_safety_recommendations(is_scam, lang_code)

    return {
        "audio_filename": original_filename,
        "duration_seconds": duration,
        "transcript": transcript,
        "translated_transcript": translated_text,
        "detected_language": lang_code,
        "language_name": lang_name,
        "is_scam": is_scam,
        "predicted_class": predicted_class,
        "confidence": confidence,
        "confidence_percentage": confidence_pct,
        "risk_level": risk_level,
        "decision_margin": ml_result.get("decision_margin") if ml_result else None,
        "indicators_detected": indicators,
        "safety_recommendations": recommendations,
        "audio_status": "Transcribed & Analyzed"
    }
