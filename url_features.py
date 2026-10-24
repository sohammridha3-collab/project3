"""
ScamShield AI — Canonical URL Feature Extraction Module
Extracts the exact lexical, structural, and statistical features expected by the
trained Phishing URL Machine Learning Classifier.
Ensures 100% consistent feature schemas between training and production inference.
"""

import math
import re
from collections import Counter
from typing import Dict, Any, List, Optional
import pandas as pd

# Target feature list matching the Kaggle Phishing URLs dataset specification
FEATURE_COLUMNS: List[str] = [
    "url_length",
    "num_dots",
    "has_https",
    "has_ip",
    "num_subdirs",
    "num_params",
    "suspicious_words",
    "tld",
    "special_char_count",
    "digits_count",
    "entropy"
]

NUMERIC_FEATURES: List[str] = [
    "url_length",
    "num_dots",
    "has_https",
    "has_ip",
    "num_subdirs",
    "num_params",
    "suspicious_words",
    "special_char_count",
    "digits_count",
    "entropy"
]

CATEGORICAL_FEATURES: List[str] = ["tld"]

# Phishing credential harvesting and scam keywords extracted from dataset analysis
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "bank", "secure", 
    "account", "confirm", "free", "bonus", "gift", "offer",
    "wallet", "password", "security", "support", "billing"
]

# Robust IPv4 and IPv6 detection regex
IPV4_REGEX = re.compile(
    r"(?:^|https?://|//)(?P<ip>(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?::\d+)?(?:/|$)"
)

# Common multi-part public suffixes to extract correct TLD
KNOWN_MULTI_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.in", "net.in", "org.in", "gov.in", "co.nz", "co.za", "com.br",
    "co.jp", "com.cn", "com.sg", "com.my", "co.kr", "com.mx", "com.ar",
    "com.tr", "com.ph", "com.hk", "com.tw"
}


def compute_shannon_entropy(text: str) -> float:
    """Computes Shannon entropy (bits per character) measuring randomness in the URL string."""
    if not text:
        return 0.0
    counts = Counter(text)
    total_len = len(text)
    return -sum((cnt / total_len) * math.log2(cnt / total_len) for cnt in counts.values())


def extract_url_features(raw_url: str) -> Dict[str, Any]:
    """
    Extracts the 11 canonical features from a URL string for machine learning inference.
    Features:
      1. url_length: Total character length of URL
      2. num_dots: Total count of '.' in URL
      3. has_https: 1 if HTTPS is indicated, 0 otherwise
      4. has_ip: 1 if hostname is an IP address, 0 otherwise
      5. num_subdirs: Count of '/' path segments in URL
      6. num_params: Count of '?' and '&' query separators
      7. suspicious_words: Count of suspicious phishing/lure keywords
      8. tld: Extracted top-level domain string (e.g. 'com', 'xyz', 'top')
      9. special_char_count: Count of special characters: - _ % @ = ~
      10. digits_count: Count of numeric digits
      11. entropy: Shannon entropy of the URL string
    """
    url_str = str(raw_url or "").strip()
    if not url_str:
        return {col: 0 if col != "tld" else "unknown" for col in FEATURE_COLUMNS}

    url_lower = url_str.lower()

    # 1. url_length
    url_len = len(url_str)

    # 2. has_https
    has_https = 1 if url_lower.startswith("https://") or ("https" in url_lower and "://" in url_str) else 0

    # 3. has_ip
    has_ip = 1 if IPV4_REGEX.search(url_str) else 0

    # 4. Clean host & path for structure metrics
    clean = re.sub(r"^[a-zA-Z]+://", "", url_str)
    # Extract host part before path or query
    host_part = clean.split("/")[0].split("?")[0].split("#")[0].split(":")[0].strip().lower()

    # 5. num_dots
    num_dots = url_str.count(".")

    # 6. num_subdirs
    num_subdirs = clean.count("/")

    # 7. num_params
    num_params = url_str.count("?") + url_str.count("&")

    # 8. suspicious_words
    suspicious_words = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # 9. special_char_count (-_%@=~)
    special_chars = sum(1 for c in url_str if c in "-_%@=~")

    # 10. digits_count
    digits_count = sum(1 for c in url_str if c.isdigit())

    # 11. entropy
    entropy = round(compute_shannon_entropy(url_str), 4)

    # 12. tld extraction
    tld = "unknown"
    if host_part and not has_ip:
        parts = host_part.split(".")
        if len(parts) >= 2:
            last_two = ".".join(parts[-2:])
            if last_two in KNOWN_MULTI_TLDS:
                tld = last_two
            else:
                last_tld = parts[-1]
                if last_tld and not last_tld.isdigit() and len(last_tld) <= 24:
                    tld = last_tld

    return {
        "url_length": url_len,
        "num_dots": num_dots,
        "has_https": has_https,
        "has_ip": has_ip,
        "num_subdirs": num_subdirs,
        "num_params": num_params,
        "suspicious_words": suspicious_words,
        "tld": tld,
        "special_char_count": special_chars,
        "digits_count": digits_count,
        "entropy": entropy
    }


def url_to_feature_dataframe(url: str, allowed_tlds: Optional[List[str]] = None) -> pd.DataFrame:
    """
    Converts a single URL into a 1-row pandas DataFrame formatted identically to the training schema.
    If allowed_tlds is provided, maps out-of-vocabulary TLDs to 'other'.
    """
    feat_dict = extract_url_features(url)
    if allowed_tlds is not None:
        tld_val = feat_dict.get("tld", "unknown")
        feat_dict["tld_top"] = tld_val if tld_val in allowed_tlds else "other"
    return pd.DataFrame([feat_dict])
