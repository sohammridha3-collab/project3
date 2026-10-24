"""
ScamShield AI — Suspicious URL & Website Scanner Service
High-performance, SSRF-protected, bounded-deadline URL and website security analysis.
Performs concurrent safe probing, TLS inspection, redirect tracking, and heuristic risk classification.
"""

import concurrent.futures
import ipaddress
import logging
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlsplit, urlunsplit, urljoin, parse_qs

logger = logging.getLogger("scamshield.url_scanner")

# -----------------------------------------------------------------------------
# CONSTANTS & CONFIGURATION
# -----------------------------------------------------------------------------

ALLOWED_SCHEMES = {"http", "https"}
TOTAL_SCAN_DEADLINE_SECONDS = 3.5
DNS_TIMEOUT_SECONDS = 1.2
SOCKET_CONNECT_TIMEOUT_SECONDS = 1.2
READ_TIMEOUT_SECONDS = 1.2
MAX_REDIRECTS = 3
MAX_RESPONSE_BYTES = 16384  # 16 KB response cap
MAX_URL_LENGTH = 2048

def get_ssl_context() -> ssl.SSLContext:
    """Creates a hardened SSL context using certifi CA bundle if available."""
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
    except Exception:
        ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx

# Multi-part public suffixes for registered domain resolution
MULTI_PART_TLDS = {
    "co.uk", "org.uk", "me.uk", "ltd.uk", "net.uk", "plc.uk", "sch.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "nic.in", "ac.in", "edu.in", "res.in", "gov.in",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.za", "net.za", "org.za", "gov.za", "ac.za",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp", "ed.jp",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    "co.kr", "ne.kr", "or.kr", "re.kr", "go.kr",
    "com.mx", "org.mx", "gob.mx", "edu.mx",
    "com.ar", "org.ar", "gob.ar", "edu.ar",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk",
    "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
    "gc.ca", "qc.ca", "on.ca", "bc.ca",
}

# Known URL shortener services (informational, not proof of malice)
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "mcaf.ee", "rebrand.ly", "cutt.ly", "tiny.cc",
    "shorturl.at", "soo.gd", "s.id", "trib.al", "linktr.ee", "rb.gy", "qr.ae"
}

# Targeted brands commonly spoofed in phishing lures
TARGETED_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "telegram", "bankofamerica", "chase", "wellsfargo",
    "citibank", "capitalone", "hsbc", "barclays", "lloyds", "santander",
    "binance", "coinbase", "metamask", "kraken", "trustwallet", "crypto",
    "usps", "fedex", "ups", "dhl", "royalmail", "auspost",
    "irs", "hmrc", "sbi", "hdfc", "icici", "axisbank", "paytm", "phonepe"
]

# High-risk TLDs with elevated abuse histories
HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click", "buzz", "club", "country", "surf", "monster", "link"
}

# Phishing credential harvesting keywords in path or query
PHISHING_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "update", "banking", "wallet",
    "security", "secure", "password", "confirm", "confirmation", "invoice", "support",
    "recovery", "authenticate", "auth", "validate", "validation", "unlock", "kyc", "suspend"
]

# Cloud metadata addresses to explicitly block
CLOUD_METADATA_IPS = {
    "169.254.169.254",   # AWS, Azure, GCP, OpenStack
    "100.100.100.200",   # Alibaba Cloud
    "169.254.170.2",     # AWS ECS container metadata
    "fd00:ec2::254"      # AWS IPv6 metadata
}

CLOUD_METADATA_HOSTNAMES = {
    "metadata.google.internal",
    "metadata.goog",
    "instance-data"
}


# -----------------------------------------------------------------------------
# SSRF PROTECTION & IP VALIDATION
# -----------------------------------------------------------------------------

class SsrfBlockError(ValueError):
    """Raised when a target URL resolves to an internal, private, loopback, or cloud metadata address."""
    pass


def is_ip_address_prohibited(ip_str: str) -> Tuple[bool, str]:
    """
    Checks if an IP address (IPv4 or IPv6) is internal, private, loopback, link-local,
    multicast, reserved, unspecified, or a cloud metadata address.
    """
    if ip_str.lower() in CLOUD_METADATA_IPS:
        return True, f"Target IP {ip_str} is a protected cloud metadata service."

    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"Invalid IP address representation: {ip_str}"

    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if ip.is_loopback:
        return True, f"Target IP {ip} is a loopback address (prohibited)."
    if ip.is_private:
        return True, f"Target IP {ip} is a private network address (RFC 1918 / RFC 4193)."
    if ip.is_link_local:
        return True, f"Target IP {ip} is a link-local address (RFC 3927 / RFC 4291)."
    if ip.is_reserved:
        return True, f"Target IP {ip} is a reserved address."
    if ip.is_multicast:
        return True, f"Target IP {ip} is a multicast address."
    if ip.is_unspecified:
        return True, f"Target IP {ip} is an unspecified address."

    # Carrier-grade NAT check (100.64.0.0/10)
    if isinstance(ip, ipaddress.IPv4Address):
        cgnat = ipaddress.ip_network("100.64.0.0/10")
        if ip in cgnat:
            return True, f"Target IP {ip} is within carrier-grade NAT / metadata address space."

    return False, ""


def resolve_and_validate_hostname(
    hostname: str, 
    dns_cache: Optional[Dict[str, List[str]]] = None,
    timeout: float = DNS_TIMEOUT_SECONDS
) -> List[str]:
    """
    Resolves hostname to IP addresses with timeout and verifies that NONE of the resolved IPs
    are prohibited internal/private/loopback/cloud-metadata addresses.
    Reuses cached resolution if dns_cache is provided.
    Raises SsrfBlockError if hostname is invalid or resolves to prohibited addresses.
    """
    clean_host = hostname.strip().lower().rstrip(".")
    if not clean_host:
        raise SsrfBlockError("Empty hostname is invalid.")

    # Check cache
    if dns_cache is not None and clean_host in dns_cache:
        return dns_cache[clean_host]

    # Check known metadata hostnames
    if clean_host in CLOUD_METADATA_HOSTNAMES or clean_host.endswith(".metadata.google.internal"):
        raise SsrfBlockError(f"Access to cloud metadata host '{hostname}' is blocked.")

    # Check localhost variations
    if clean_host == "localhost" or clean_host.endswith(".localhost") or clean_host.endswith(".local") or clean_host.endswith(".internal"):
        raise SsrfBlockError(f"Access to local or internal host '{hostname}' is blocked.")

    # If the hostname is already an IP address literal
    try:
        prohibited, reason = is_ip_address_prohibited(clean_host.strip("[]"))
        if prohibited:
            raise SsrfBlockError(f"Prohibited destination: {reason}")
        res = [clean_host.strip("[]")]
        if dns_cache is not None:
            dns_cache[clean_host] = res
        return res
    except ValueError:
        pass  # Not an IP literal, proceed to DNS resolution

    def _do_lookup():
        return socket.getaddrinfo(clean_host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_do_lookup)
            addr_info = future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        raise ValueError(f"DNS lookup timed out ({timeout}s) for hostname '{hostname}'.")
    except socket.gaierror as e:
        raise ValueError(f"DNS resolution failed for hostname '{hostname}': {e.strerror or str(e)}")
    except Exception as e:
        raise ValueError(f"DNS lookup error for hostname '{hostname}': {str(e)}")

    if not addr_info:
        raise ValueError(f"No DNS records found for hostname '{hostname}'.")

    resolved_ips = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)

    # Validate EVERY resolved IP address against SSRF
    for ip in resolved_ips:
        prohibited, reason = is_ip_address_prohibited(ip)
        if prohibited:
            raise SsrfBlockError(f"DNS resolution for '{hostname}' resolved to prohibited address ({ip}): {reason}")

    if dns_cache is not None:
        dns_cache[clean_host] = resolved_ips

    return resolved_ips


# -----------------------------------------------------------------------------
# DOMAIN & PUBLIC SUFFIX EXTRACTION
# -----------------------------------------------------------------------------

def extract_registered_domain(hostname: str) -> Tuple[str, str, str]:
    """
    Extracts (subdomain, registered_domain, tld) from a hostname using
    known multi-part public suffixes and standard single-part TLD logic.
    """
    clean_host = hostname.strip().lower().rstrip(".")
    if not clean_host:
        return "", "", ""

    try:
        ipaddress.ip_address(clean_host.strip("[]"))
        return "", clean_host, ""
    except ValueError:
        pass

    parts = clean_host.split(".")
    if len(parts) <= 1:
        return "", clean_host, ""

    matched_tld = None
    if len(parts) >= 2:
        two_part = f"{parts[-2]}.{parts[-1]}"
        if two_part in MULTI_PART_TLDS:
            matched_tld = two_part

    if matched_tld:
        tld_parts_count = 2
    else:
        matched_tld = parts[-1]
        tld_parts_count = 1

    remaining_parts = parts[:-tld_parts_count]
    if not remaining_parts:
        return "", clean_host, matched_tld

    domain_label = remaining_parts[-1]
    registered_domain = f"{domain_label}.{matched_tld}"
    subdomain = ".".join(remaining_parts[:-1])

    return subdomain, registered_domain, matched_tld


# -----------------------------------------------------------------------------
# URL NORMALIZATION & VALIDATION
# -----------------------------------------------------------------------------

def normalize_and_validate_url(raw_url: str) -> Tuple[str, Dict[str, Any]]:
    """
    Validates scheme, normalizes format, and parses URL components safely.
    Rejects unsupported schemes (file:, javascript:, data:, ftp:, etc.).
    Returns (normalized_url, parsed_components).
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValueError("URL cannot be empty.")

    clean_url = raw_url.strip()
    if len(clean_url) > MAX_URL_LENGTH:
        raise ValueError(f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters.")

    if any(ord(c) < 32 or ord(c) == 127 for c in clean_url):
        raise ValueError("URL contains prohibited control characters.")

    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", clean_url)
    if not scheme_match:
        clean_url = "https://" + clean_url
        scheme = "https"
    else:
        scheme = scheme_match.group(1).lower()

    if scheme not in ALLOWED_SCHEMES:
        raise ValueError(
            f"Unsupported URL scheme '{scheme}:'. ScamShield only accepts 'http' and 'https' URLs. "
            f"Schemes such as 'javascript:', 'file:', 'data:', or 'ftp:' are rejected for security."
        )

    try:
        parts = urlsplit(clean_url)
    except Exception as e:
        raise ValueError(f"Unable to parse URL structure: {str(e)}")

    if not parts.netloc:
        raise ValueError("URL is missing a valid destination hostname or authority.")

    has_userinfo = "@" in parts.netloc
    userinfo = ""
    netloc_without_userinfo = parts.netloc
    if has_userinfo:
        userinfo, netloc_without_userinfo = parts.netloc.split("@", 1)

    port = None
    host = netloc_without_userinfo
    if ":" in netloc_without_userinfo and not netloc_without_userinfo.endswith("]"):
        h_part, p_part = netloc_without_userinfo.rsplit(":", 1)
        if p_part.isdigit():
            port = int(p_part)
            host = h_part

    host = host.strip("[]").strip().lower()
    if not host:
        raise ValueError("URL contains an empty or malformed hostname.")

    punycode_host = host
    unicode_host = host
    has_punycode = False
    try:
        punycode_host = host.encode("idna").decode("ascii")
        unicode_host = host.encode("ascii").decode("idna")
        if punycode_host.startswith("xn--") or ".xn--" in punycode_host:
            has_punycode = True
    except Exception:
        pass

    path = parts.path or "/"

    netloc_normalized = punycode_host
    if port:
        if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
            netloc_normalized = f"{punycode_host}:{port}"

    normalized_url = urlunsplit((scheme, netloc_normalized, path, parts.query, parts.fragment))

    components = {
        "scheme": scheme,
        "raw_netloc": parts.netloc,
        "host": host,
        "punycode_host": punycode_host,
        "unicode_host": unicode_host,
        "has_punycode": has_punycode,
        "port": port or (443 if scheme == "https" else 80),
        "path": path,
        "query": parts.query,
        "fragment": parts.fragment,
        "has_userinfo": has_userinfo,
        "userinfo": userinfo
    }

    return normalized_url, components


# -----------------------------------------------------------------------------
# HEURISTIC & STRUCTURAL ANALYSIS (PHASE 3.A)
# -----------------------------------------------------------------------------

def analyze_url_structure(raw_url: str, normalized_url: str, components: Dict[str, Any]) -> Dict[str, Any]:
    """
    Performs deterministic heuristic inspections on the URL structure.
    Avoids double-counting multiple indicators representing the same issue.
    """
    t_start = time.perf_counter()
    findings: List[str] = []
    checks: List[Dict[str, Any]] = []
    threat_points = 0.0

    host = components["punycode_host"]
    unicode_host = components["unicode_host"]
    path = components["path"]
    query = components["query"]

    # 1. Deceptive '@' Symbol Check
    t0 = time.perf_counter()
    if components["has_userinfo"]:
        userinfo_text = components["userinfo"]
        findings.append(
            f"Deceptive userinfo syntax (@) detected. Browsers may interpret '{userinfo_text}' as credentials "
            f"while navigating to destination '{host}'."
        )
        checks.append({
            "name": "Deceptive Userinfo (@) Check",
            "category": "Structure",
            "status": "fail",
            "description": "Checks if the URL embeds fake domain names before an '@' delimiter.",
            "details": f"Detected embedded userinfo '{userinfo_text}' preceding destination '{host}'.",
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2)
        })
        threat_points += 35.0
    else:
        checks.append({
            "name": "Deceptive Userinfo (@) Check",
            "category": "Structure",
            "status": "pass",
            "description": "Checks if the URL embeds fake domain names before an '@' delimiter.",
            "details": "No misleading userinfo or '@' delimiter found in URL authority.",
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2)
        })

    # 2. Punycode & IDN Homoglyph Check
    t0 = time.perf_counter()
    is_punycode = components["has_punycode"]
    has_non_ascii = any(ord(c) > 127 for c in host)
    if is_punycode or has_non_ascii:
        findings.append(
            f"Internationalized Domain / Punycode detected: '{host}' (renders as '{unicode_host}'). "
            f"Often leveraged in homoglyph spoofing attacks."
        )
        checks.append({
            "name": "Punycode & Homoglyph Inspection",
            "category": "Domain",
            "status": "warning",
            "description": "Screens for internationalized characters spoofing Latin script.",
            "details": f"Punycode encoded host: '{host}' (Unicode: '{unicode_host}').",
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2)
        })
        threat_points += 30.0
    else:
        checks.append({
            "name": "Punycode & Homoglyph Inspection",
            "category": "Domain",
            "status": "pass",
            "description": "Screens for internationalized characters spoofing Latin script.",
            "details": "Host uses standard ASCII characters with no punycode representation.",
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2)
        })

    # 3. Host Identity Format (IP-Address vs Domain) Check
    t0 = time.perf_counter()
    is_ip_host = False
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip_host = True
    except ValueError:
        is_ip_host = False

    if is_ip_host:
        findings.append(
            f"Destination host is a raw IP address ({host}) rather than a registered domain name. "
            f"Legitimate websites standardly utilize registered domain names."
        )
        checks.append({
            "name": "Host Identity Format",
            "category": "Domain",
            "status": "warning",
            "description": "Verifies that the URL uses a domain name rather than a raw IP address.",
            "details": f"Host '{host}' is an IP address literal.",
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2)
        })
        threat_points += 25.0
    else:
        checks.append({
            "name": "Host Identity Format",
            "category": "Domain",
            "status": "pass",
            "description": "Verifies that the URL uses a domain name rather than a raw IP address.",
            "details": f"Host '{host}' is a standard domain name.",
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2)
        })

    # 4. Registered Domain & Subdomain Structure
    t0 = time.perf_counter()
    subdomain, registered_domain, tld = extract_registered_domain(host)
    subdomain_parts = [p for p in subdomain.split(".") if p] if subdomain else []
    subdomain_count = len(subdomain_parts)

    # 5. Brand Spoofing Check (Check first to avoid double counting with subdomains/path)
    impersonated_brand = None
    brand_in_subdomain = False
    brand_in_path = False

    for brand in TARGETED_BRANDS:
        reg_domain_label = registered_domain.split(".")[0] if "." in registered_domain else registered_domain
        if reg_domain_label != brand:
            if subdomain and brand in subdomain:
                impersonated_brand = brand
                brand_in_subdomain = True
                break
            elif brand in path.lower():
                impersonated_brand = brand
                brand_in_path = True
                break

    if impersonated_brand:
        findings.append(
            f"Potential brand impersonation: Keyword '{impersonated_brand}' appears in the subdomain or path, "
            f"but the registered domain is '{registered_domain}'. Common indicator of phishing lures."
        )
        checks.append({
            "name": "Brand Impersonation & Typosquatting",
            "category": "Heuristics",
            "status": "warning",
            "description": "Checks if prominent brand names are embedded in unassociated domains.",
            "details": f"Keyword '{impersonated_brand}' found on unrelated domain '{registered_domain}'.",
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2)
        })
        threat_points += 35.0
    else:
        checks.append({
            "name": "Brand Impersonation & Typosquatting",
            "category": "Heuristics",
            "status": "pass",
            "description": "Checks if prominent brand names are embedded in unassociated domains.",
            "details": "No high-risk brand impersonation patterns detected in subdomain/path.",
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2)
        })

    # 6. Subdomain Depth (only penalize if brand spoofing wasn't already penalized for it)
    t0 = time.perf_counter()
    if subdomain_count >= 3:
        if not brand_in_subdomain:
            findings.append(f"Excessive subdomain nesting ({subdomain_count} levels: '{subdomain}').")
            threat_points += 15.0
        checks.append({
            "name": "Subdomain Structure & Depth",
            "category": "Domain",
            "status": "warning",
            "description": "Evaluates subdomain nesting levels against typical legitimate structures.",
            "details": f"Subdomain has {subdomain_count} nested levels: '{subdomain}'.",
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2)
        })
    else:
        checks.append({
            "name": "Subdomain Structure & Depth",
            "category": "Domain",
            "status": "pass",
            "description": "Evaluates subdomain nesting levels against typical legitimate structures.",
            "details": f"Subdomain structure is within typical bounds ({subdomain_count} subdomains).",
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2)
        })

    # 7. High-Risk TLD Check
    t0 = time.perf_counter()
    if tld.lower() in HIGH_RISK_TLDS:
        findings.append(f"Domain uses high-abuse or high-risk top-level domain ('.{tld}').")
        checks.append({
            "name": "Top-Level Domain Reputation",
            "category": "Domain",
            "status": "warning",
            "description": "Evaluates TLD against historically elevated phishing and abuse registries.",
            "details": f"Domain extension '.{tld}' is associated with elevated registration abuse.",
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2)
        })
        threat_points += 15.0
    else:
        checks.append({
            "name": "Top-Level Domain Reputation",
            "category": "Domain",
            "status": "pass",
            "description": "Evaluates TLD against historically elevated phishing and abuse registries.",
            "details": f"Top-level domain '.{tld}' is a recognized standard registry.",
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2)
        })

    # 8. Known URL Shortener Detection (Informational, NOT proof of malice)
    t0 = time.perf_counter()
    is_shortener = registered_domain.lower() in URL_SHORTENERS or host.lower() in URL_SHORTENERS
    if is_shortener:
        findings.append(
            f"URL shortener detected ({registered_domain}). Shorteners conceal the final destination "
            f"until resolved by an HTTP client. Note: Shorteners are widely used for legitimate links as well."
        )
        checks.append({
            "name": "URL Shortener Detection",
            "category": "Domain",
            "status": "info",
            "description": "Identifies link-shortening services that conceal the destination.",
            "details": f"Domain '{registered_domain}' is a recognized URL shortening service (Informational).",
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2)
        })
        # Shortener alone does not prove malicious intent: 0 threat points
    else:
        checks.append({
            "name": "URL Shortener Detection",
            "category": "Domain",
            "status": "pass",
            "description": "Identifies link-shortening services that conceal the destination.",
            "details": "Destination does not appear to be a known URL shortener service.",
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2)
        })

    # 9. Credential Harvesting Keywords in Path / Query
    t0 = time.perf_counter()
    search_space = (path + " " + query).lower()
    matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in search_space]

    if (len(matched_keywords) >= 2 or (len(matched_keywords) >= 1 and impersonated_brand)) and not brand_in_path:
        findings.append(f"Credential harvesting keywords detected in URL path/query: {', '.join(matched_keywords[:4])}")
        checks.append({
            "name": "Credential Harvesting Keywords",
            "category": "Heuristics",
            "status": "warning",
            "description": "Inspects path and query strings for authentication or banking lure terms.",
            "details": f"Matched keywords: {', '.join(matched_keywords[:4])}.",
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2)
        })
        threat_points += 15.0
    else:
        checks.append({
            "name": "Credential Harvesting Keywords",
            "category": "Heuristics",
            "status": "pass",
            "description": "Inspects path and query strings for authentication or banking lure terms.",
            "details": "No suspicious cluster of credential-harvesting keywords found in path/query.",
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2)
        })

    # 10. URL Length & Encoding Obfuscation
    t0 = time.perf_counter()
    url_len = len(normalized_url)
    if "%25" in raw_url:
        findings.append("Double percent-encoding (%25) detected in URL. May indicate evasion techniques.")
        checks.append({
            "name": "URL Length & Encoding Obfuscation",
            "category": "Structure",
            "status": "warning",
            "description": "Inspects URL length and potential parameter padding.",
            "details": "Double percent-encoding detected in URL parameters.",
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2)
        })
        threat_points += 10.0
    elif url_len > 150:
        checks.append({
            "name": "URL Length & Encoding Obfuscation",
            "category": "Structure",
            "status": "info",
            "description": "Inspects URL length and potential parameter padding.",
            "details": f"Length: {url_len} characters (Informational).",
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2)
        })
    else:
        checks.append({
            "name": "URL Length & Encoding Obfuscation",
            "category": "Structure",
            "status": "pass",
            "description": "Inspects URL length and potential parameter padding.",
            "details": f"URL length is within standard parameters ({url_len} chars).",
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2)
        })

    # Bound heuristic threat points (max 85.0 from heuristics alone)
    bounded_threat_points = min(threat_points, 85.0)

    return {
        "findings": findings,
        "checks": checks,
        "threat_points": bounded_threat_points,
        "impersonated_brand": impersonated_brand,
        "domain_info": {
            "host": host,
            "unicode_host": unicode_host,
            "subdomain": subdomain,
            "registered_domain": registered_domain,
            "tld": tld,
            "is_ip_host": is_ip_host,
            "has_punycode": components["has_punycode"],
            "is_shortener": is_shortener
        },
        "duration_ms": round((time.perf_counter() - t_start) * 1000, 2)
    }


# -----------------------------------------------------------------------------
# SAFE TLS & CERTIFICATE INSPECTION (PHASE 3.B)
# -----------------------------------------------------------------------------

def inspect_tls_certificate(
    hostname: str, 
    port: int = 443, 
    target_ip: Optional[str] = None,
    timeout: float = SOCKET_CONNECT_TIMEOUT_SECONDS
) -> Dict[str, Any]:
    """
    Safely inspects the TLS certificate of an HTTPS host within the specified timeout.
    Connects to target_ip while pinning server_hostname to prevent DNS rebinding.
    """
    t_start = time.perf_counter()
    cert_info: Dict[str, Any] = {
        "inspected": False,
        "valid": False,
        "issuer": None,
        "subject": None,
        "expires": None,
        "san_domains": [],
        "notes": "",
        "duration_ms": 0.0
    }

    ctx = get_ssl_context()

    connect_host = target_ip if target_ip else hostname
    connect_timeout = max(0.5, min(timeout, SOCKET_CONNECT_TIMEOUT_SECONDS))

    try:
        with socket.create_connection((connect_host, port), timeout=connect_timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    cert_info["notes"] = "Server presented no TLS certificate."
                    cert_info["duration_ms"] = round((time.perf_counter() - t_start) * 1000, 2)
                    return cert_info

                cert_info["inspected"] = True
                cert_info["valid"] = True

                issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                cert_info["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown Issuer"

                subject_dict = dict(x[0] for x in cert.get("subject", ()))
                cert_info["subject"] = subject_dict.get("commonName") or "Unknown Subject"
                cert_info["expires"] = cert.get("notAfter")

                san_list = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
                cert_info["san_domains"] = san_list[:10]
                cert_info["notes"] = f"Valid TLS certificate issued by {cert_info['issuer']}."

    except ssl.SSLCertVerificationError as cert_err:
        cert_info["inspected"] = True
        cert_info["valid"] = False
        cert_info["notes"] = f"Certificate verification failed: {cert_err.verify_message or str(cert_err)}"
    except socket.timeout:
        cert_info["inspected"] = False
        cert_info["valid"] = False
        cert_info["notes"] = f"TLS handshake timed out after {connect_timeout}s."
    except Exception as exc:
        cert_info["inspected"] = False
        cert_info["valid"] = False
        cert_info["notes"] = f"TLS inspection unavailable ({type(exc).__name__})."

    cert_info["duration_ms"] = round((time.perf_counter() - t_start) * 1000, 2)
    return cert_info


# -----------------------------------------------------------------------------
# CONTROLLED REDIRECT & LIVE PROBE (PHASE 3.D & PHASE 4)
# -----------------------------------------------------------------------------

def probe_url_and_follow_redirects(
    initial_url: str,
    components: Dict[str, Any],
    dns_cache: Optional[Dict[str, List[str]]] = None,
    max_redirects: int = MAX_REDIRECTS,
    deadline_seconds: float = 3.0
) -> Dict[str, Any]:
    """
    Safely executes controlled server-side redirect inspection:
    - Bounded by deadline_seconds total duration.
    - Re-validates DNS and checks for SSRF at EVERY redirect step.
    - Limits response download size (max 16 KB).
    - Captures redirect chain and HTTP status codes.
    - Never executes JavaScript or renders remote HTML.
    """
    import urllib.request
    from urllib.error import HTTPError, URLError

    t_start = time.perf_counter()
    redirect_chain: List[Dict[str, Any]] = []
    current_url = initial_url
    final_destination = initial_url
    status_code = None
    content_type = ""
    error_note = None

    class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    https_handler = urllib.request.HTTPSHandler(context=get_ssl_context())
    opener = urllib.request.build_opener(NoRedirectHandler, https_handler)
    opener.addheaders = [
        ("User-Agent", "ScamShieldAI-UrlScanner/1.0 (+https://project3-backend-fzlv.onrender.com)"),
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    ]

    for hop in range(max_redirects + 1):
        # Check deadline
        elapsed = time.perf_counter() - t_start
        remaining = deadline_seconds - elapsed
        if remaining <= 0.4:
            error_note = f"Inspection stopped: Scan deadline reached after {hop} hop(s)."
            break

        # 1. Parse current hop destination
        try:
            norm_hop, hop_components = normalize_and_validate_url(current_url)
        except Exception as e:
            error_note = f"Redirect target rejected: {str(e)}"
            break

        # 2. SSRF check on hop host with timeout
        try:
            hop_dns_timeout = min(remaining * 0.5, DNS_TIMEOUT_SECONDS)
            resolved_ips = resolve_and_validate_hostname(
                hop_components["punycode_host"], 
                dns_cache=dns_cache,
                timeout=max(0.4, hop_dns_timeout)
            )
        except SsrfBlockError as ssrf_err:
            error_note = f"Redirect to prohibited destination blocked (SSRF Protection): {str(ssrf_err)}"
            redirect_chain.append({
                "hop": hop,
                "url": current_url,
                "status": "Blocked",
                "reason": str(ssrf_err)
            })
            break
        except Exception as dns_err:
            error_note = f"DNS resolution failed at hop {hop}: {str(dns_err)}"
            break

        # 3. Controlled network request with timeout
        req = urllib.request.Request(norm_hop, headers={
            "User-Agent": "ScamShieldAI-UrlScanner/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        })

        hop_connect_timeout = max(0.5, min(remaining - 0.2, SOCKET_CONNECT_TIMEOUT_SECONDS + READ_TIMEOUT_SECONDS))

        try:
            with opener.open(req, timeout=hop_connect_timeout) as resp:
                status_code = resp.status
                content_type = resp.headers.get_content_type()
                final_destination = norm_hop

                # Read only up to MAX_RESPONSE_BYTES
                _ = resp.read(MAX_RESPONSE_BYTES)

                redirect_chain.append({
                    "hop": hop,
                    "url": norm_hop,
                    "status_code": status_code,
                    "content_type": content_type
                })
                break

        except HTTPError as http_err:
            status_code = http_err.code
            content_type = http_err.headers.get_content_type() if http_err.headers else ""

            if status_code in (301, 302, 303, 307, 308) and "Location" in http_err.headers:
                location = http_err.headers["Location"]
                redirect_chain.append({
                    "hop": hop,
                    "url": norm_hop,
                    "status_code": status_code,
                    "location": location
                })
                next_url = urljoin(norm_hop, location)

                if any(r.get("url") == next_url for r in redirect_chain):
                    error_note = f"Redirect loop detected at '{next_url}'."
                    break

                current_url = next_url
                final_destination = next_url
                continue
            else:
                redirect_chain.append({
                    "hop": hop,
                    "url": norm_hop,
                    "status_code": status_code,
                    "content_type": content_type
                })
                final_destination = norm_hop
                break

        except (URLError, socket.timeout, TimeoutError) as net_err:
            error_note = f"Connection failed or timed out: {str(net_err)}"
            redirect_chain.append({
                "hop": hop,
                "url": norm_hop,
                "status_code": "Timeout/Error",
                "error": str(net_err)
            })
            break
        except Exception as general_err:
            error_note = f"Request inspection error: {str(general_err)}"
            break

    total_duration_ms = round((time.perf_counter() - t_start) * 1000, 2)

    return {
        "status_code": status_code,
        "redirect_count": len(redirect_chain) - 1 if len(redirect_chain) > 1 else 0,
        "redirect_chain": redirect_chain,
        "final_destination": final_destination,
        "error_note": error_note,
        "content_type": content_type,
        "duration_ms": total_duration_ms
    }


# -----------------------------------------------------------------------------
# THREAT INTELLIGENCE CONNECTOR (PHASE 3.C)
# -----------------------------------------------------------------------------

def check_threat_intelligence(url: str, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Checks threat intelligence feeds ONLY if an explicit API key is configured.
    If no key is configured, transparently reports that live reputation check
    was not performed. Never invents fake matches!
    """
    t_start = time.perf_counter()
    gsb_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not gsb_key and not vt_key:
        return {
            "configured": False,
            "provider": "None configured",
            "checked": False,
            "matched": False,
            "threat_type": None,
            "notes": "No external threat-intelligence API key (e.g. Google Safe Browsing or VirusTotal) configured on backend. Live reputation database check was skipped.",
            "duration_ms": round((time.perf_counter() - t_start) * 1000, 2)
        }

    if gsb_key:
        try:
            import httpx
            endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_key}"
            payload = {
                "client": {"clientId": "scamshield-ai", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            client_timeout = max(0.5, min(timeout, 2.0))
            with httpx.Client(timeout=client_timeout) as client:
                res = client.post(endpoint, json=payload)
                if res.status_code == 200:
                    data = res.json()
                    matches = data.get("matches", [])
                    if matches:
                        t_type = matches[0].get("threatType", "MALICIOUS")
                        return {
                            "configured": True,
                            "provider": "Google Safe Browsing v4",
                            "checked": True,
                            "matched": True,
                            "threat_type": t_type,
                            "notes": f"Flagged by Google Safe Browsing as {t_type}.",
                            "duration_ms": round((time.perf_counter() - t_start) * 1000, 2)
                        }
                    return {
                        "configured": True,
                        "provider": "Google Safe Browsing v4",
                        "checked": True,
                        "matched": False,
                        "threat_type": None,
                        "notes": "No active threat matches found in Google Safe Browsing database.",
                        "duration_ms": round((time.perf_counter() - t_start) * 1000, 2)
                    }
        except Exception as e:
            logger.warning(f"Google Safe Browsing check failed: {e}")
            return {
                "configured": True,
                "provider": "Google Safe Browsing v4",
                "checked": False,
                "matched": False,
                "threat_type": None,
                "notes": f"Threat intelligence request failed or timed out: {str(e)}",
                "duration_ms": round((time.perf_counter() - t_start) * 1000, 2)
            }

    return {
        "configured": False,
        "provider": "None configured",
        "checked": False,
        "matched": False,
        "threat_type": None,
        "notes": "Threat intelligence provider configured but inactive.",
        "duration_ms": round((time.perf_counter() - t_start) * 1000, 2)
    }


# -----------------------------------------------------------------------------
# MAIN HIGH-SPEED PARALLEL SCANNER PIPELINE
# -----------------------------------------------------------------------------

def scan_url(raw_url: str, deadline: float = TOTAL_SCAN_DEADLINE_SECONDS) -> Dict[str, Any]:
    """
    Executes complete, fast, concurrent, SSRF-safe URL inspection:
    1. Normalization & validation.
    2. Pre-flight SSRF & DNS resolution with local scan-scoped cache.
    3. Structural & brand impersonation heuristics.
    4. Concurrent execution of TLS inspection, redirect probing, and threat intel.
    5. Calibrated classification: Low Risk, Suspicious, High Risk, or Unknown.
    """
    t_start = time.perf_counter()
    scan_timestamp = datetime.now(timezone.utc)
    dns_cache: Dict[str, List[str]] = {}

    # Phase 1: Normalize & Validate URL
    normalized_url, components = normalize_and_validate_url(raw_url)

    # Phase 2: SSRF Pre-flight DNS validation
    primary_ip = None
    dns_error = None
    try:
        resolved_ips = resolve_and_validate_hostname(
            components["punycode_host"], 
            dns_cache=dns_cache, 
            timeout=DNS_TIMEOUT_SECONDS
        )
        primary_ip = resolved_ips[0] if resolved_ips else None
    except SsrfBlockError as ssrf_err:
        # Strict security: SSRF attempts are rejected immediately
        raise ssrf_err
    except Exception as dns_exc:
        # DNS failed, server not resolvable
        dns_error = str(dns_exc)

    # Phase 3: URL Structure & Heuristic Analysis (in-memory, <1ms)
    structure_res = analyze_url_structure(raw_url, normalized_url, components)
    findings = list(structure_res["findings"])
    checks = list(structure_res["checks"])
    threat_points = structure_res["threat_points"]
    impersonated_brand = structure_res["impersonated_brand"]

    # If DNS resolution failed completely, we cannot execute active network probing
    if dns_error:
        elapsed_total = round((time.perf_counter() - t_start) * 1000, 1)
        checks.append({
            "name": "DNS Resolution & SSRF Policy",
            "category": "Network",
            "status": "unavailable",
            "description": "Verifies destination host domain name resolution and SSRF policy.",
            "details": f"DNS resolution failed: {dns_error}. Host may be offline or non-existent.",
            "duration_ms": elapsed_total
        })
        checks.append({
            "name": "HTTPS & TLS Security",
            "category": "Encryption",
            "status": "unavailable",
            "description": "Verifies valid SSL/TLS certificate configuration.",
            "details": "TLS inspection unavailable: Host could not be resolved via DNS.",
            "duration_ms": 0.0
        })
        checks.append({
            "name": "Server Reachability",
            "category": "Network",
            "status": "unavailable",
            "description": "Checks if the remote web server responds to HTTP requests.",
            "details": f"Unreachable: {dns_error}.",
            "duration_ms": 0.0
        })

        # Classification for unresolvable host:
        # If severe heuristics are detected (e.g. deceptive @ or brand spoofing), mark Suspicious/High Risk.
        # Otherwise, mark Unknown (insufficient evidence to assess a non-existent or unresolvable destination).
        if threat_points >= 35.0:
            classification = "High Risk" if threat_points >= 50.0 else "Suspicious"
            risk_score = threat_points
            findings.append(f"Host does not resolve via DNS ({dns_error}), but severe phishing patterns were detected in the URL structure.")
        else:
            classification = "Unknown"
            risk_score = 0.0
            findings.append(f"Host '{components['host']}' could not be resolved via DNS. Destination is inactive, unreachble, or expired. Insufficient evidence to evaluate safety.")

        recommendations = [
            "This web destination could not be located via DNS and may be defunct, misspelled, or taken down.",
            "Do not attempt to navigate to alternative links provided in the same communication.",
            "Verify the intended destination address carefully."
        ]

        return {
            "url": raw_url,
            "normalized_url": normalized_url,
            "classification": classification,
            "risk_score": risk_score,
            "checks": checks,
            "findings": findings,
            "recommendations": recommendations,
            "scan_timestamp": scan_timestamp,
            "domain_info": structure_res["domain_info"],
            "https_info": {
                "is_https": components["scheme"] == "https",
                "cert_valid": None,
                "issuer": None,
                "subject": None,
                "expires": None
            },
            "redirect_info": {
                "redirect_count": 0,
                "final_destination": normalized_url,
                "chain": []
            },
            "threat_intel_info": {
                "configured": False,
                "checked": False,
                "matched": False,
                "notes": "Skipped due to DNS resolution failure."
            },
            "resolved_ip": None,
            "scan_duration_ms": elapsed_total,
            "disclaimer": "Automated security checks evaluate observed technical indicators and heuristics. They cannot guarantee that a website is free from fraud, social engineering, or emerging threats."
        }

    # Add DNS check status
    checks.append({
        "name": "DNS Resolution & SSRF Policy",
        "category": "Network",
        "status": "pass",
        "description": "Verifies destination host domain name resolution and SSRF policy.",
        "details": f"Host '{components['host']}' resolved to valid public IP ({primary_ip}). SSRF defenses passed.",
        "duration_ms": round((time.perf_counter() - t_start) * 1000, 2)
    })

    # Phases 4, 5, 6: CONCURRENT NETWORK PROBING BOUNDED BY DEADLINE
    is_https = components["scheme"] == "https"
    remaining_time = max(0.8, deadline - (time.perf_counter() - t_start))

    tls_future = None
    probe_future = None
    intel_future = None

    tls_info = None
    probe_res = None
    threat_intel = None

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        # Task A: TLS Certificate Inspection (only if HTTPS)
        if is_https:
            tls_future = executor.submit(
                inspect_tls_certificate,
                components["punycode_host"],
                components["port"],
                primary_ip,
                min(remaining_time, 2.0)
            )

        # Task B: Controlled Redirect & HTTP Reachability Probe
        probe_future = executor.submit(
            probe_url_and_follow_redirects,
            normalized_url,
            components,
            dns_cache,
            MAX_REDIRECTS,
            remaining_time
        )

        # Task C: Threat Intelligence Query (if API key configured)
        intel_future = executor.submit(
            check_threat_intelligence,
            normalized_url,
            min(remaining_time, 2.0)
        )

        # Gather TLS
        if tls_future:
            try:
                tls_info = tls_future.result(timeout=remaining_time + 0.2)
            except Exception as e:
                tls_info = {
                    "inspected": False,
                    "valid": False,
                    "notes": f"TLS inspection timed out: {e}",
                    "duration_ms": round(remaining_time * 1000, 1)
                }

        # Gather Probe
        if probe_future:
            try:
                probe_res = probe_future.result(timeout=remaining_time + 0.2)
            except Exception as e:
                probe_res = {
                    "status_code": None,
                    "redirect_count": 0,
                    "redirect_chain": [],
                    "final_destination": normalized_url,
                    "error_note": f"Server probe timed out: {e}",
                    "content_type": "",
                    "duration_ms": round(remaining_time * 1000, 1)
                }

        # Gather Intel
        if intel_future:
            try:
                threat_intel = intel_future.result(timeout=remaining_time + 0.2)
            except Exception as e:
                threat_intel = {
                    "configured": True,
                    "provider": "Threat Intel",
                    "checked": False,
                    "matched": False,
                    "threat_type": None,
                    "notes": f"Threat intel query timed out: {e}",
                    "duration_ms": 0.0
                }

    # Evaluate Phase 4: TLS Check Results
    if is_https:
        if tls_info and tls_info["inspected"] and tls_info["valid"]:
            checks.append({
                "name": "HTTPS & TLS Security",
                "category": "Encryption",
                "status": "pass",
                "description": "Verifies valid SSL/TLS certificate configuration.",
                "details": f"Valid certificate presented by {tls_info['issuer']}. Note: HTTPS encrypts data in transit but does NOT guarantee website legitimacy.",
                "duration_ms": tls_info["duration_ms"]
            })
        elif tls_info and tls_info["inspected"] and not tls_info["valid"]:
            findings.append(f"Invalid or self-signed TLS certificate: {tls_info['notes']}")
            checks.append({
                "name": "HTTPS & TLS Security",
                "category": "Encryption",
                "status": "fail",
                "description": "Verifies valid SSL/TLS certificate configuration.",
                "details": tls_info["notes"],
                "duration_ms": tls_info["duration_ms"]
            })
            threat_points += 20.0
        else:
            checks.append({
                "name": "HTTPS & TLS Security",
                "category": "Encryption",
                "status": "unavailable",
                "description": "Verifies valid SSL/TLS certificate configuration.",
                "details": f"TLS inspection could not be completed ({tls_info['notes'] if tls_info else 'Unavailable'}).",
                "duration_ms": tls_info["duration_ms"] if tls_info else 0.0
            })
    else:
        # HTTP is informational/warning regarding transport encryption; does NOT make it a scam
        findings.append("URL uses plain HTTP protocol without transport layer TLS encryption.")
        checks.append({
            "name": "HTTPS & TLS Security",
            "category": "Encryption",
            "status": "warning",
            "description": "Verifies whether connection uses encrypted HTTPS protocol.",
            "details": "Plain HTTP protocol in use; communications are not encrypted in transit (Note: HTTP alone does not prove fraud).",
            "duration_ms": 0.0
        })

    # Evaluate Phase 5: Redirects & Server Reachability
    redirect_count = probe_res["redirect_count"] if probe_res else 0
    final_dest = probe_res["final_destination"] if probe_res else normalized_url
    probe_duration = probe_res["duration_ms"] if probe_res else 0.0

    if redirect_count > 0:
        findings.append(f"URL triggered {redirect_count} redirect(s), landing at '{final_dest}'.")
        checks.append({
            "name": "Redirect Destination Tracking",
            "category": "Network",
            "status": "info" if redirect_count <= 2 else "warning",
            "description": "Inspects server-side redirect hops to identify final landing page.",
            "details": f"{redirect_count} redirect(s) followed. Final landing destination: '{final_dest}'",
            "duration_ms": probe_duration
        })
        if redirect_count >= 3:
            threat_points += 10.0
    else:
        checks.append({
            "name": "Redirect Destination Tracking",
            "category": "Network",
            "status": "pass",
            "description": "Inspects server-side redirect hops to identify final landing page.",
            "details": "No external redirects encountered.",
            "duration_ms": probe_duration
        })

    is_server_unreachable = False
    if probe_res and probe_res["error_note"]:
        is_server_unreachable = True
        checks.append({
            "name": "Server Reachability",
            "category": "Network",
            "status": "unavailable",
            "description": "Checks if the remote web server responds to HTTP requests.",
            "details": f"Probe error: {probe_res['error_note']}",
            "duration_ms": probe_duration
        })
    else:
        checks.append({
            "name": "Server Reachability",
            "category": "Network",
            "status": "pass",
            "description": "Checks if the remote web server responds to HTTP requests.",
            "details": f"Server responded with HTTP {probe_res['status_code'] if probe_res else '200'}.",
            "duration_ms": probe_duration
        })

    # Evaluate Phase 6: Threat Intelligence
    intel_duration = threat_intel["duration_ms"] if threat_intel else 0.0
    is_intel_match = False

    if threat_intel and threat_intel["matched"]:
        is_intel_match = True
        threat_points += 60.0
        findings.append(f"Threat Intelligence Alert: URL matches known malicious database ({threat_intel['threat_type']}).")
        checks.append({
            "name": "Reputation & Threat Intelligence",
            "category": "Threat Intelligence",
            "status": "fail",
            "description": "Cross-references submitted URL against active threat intelligence databases.",
            "details": threat_intel["notes"],
            "duration_ms": intel_duration
        })
    elif threat_intel and threat_intel["checked"]:
        checks.append({
            "name": "Reputation & Threat Intelligence",
            "category": "Threat Intelligence",
            "status": "pass",
            "description": "Cross-references submitted URL against active threat intelligence databases.",
            "details": threat_intel["notes"],
            "duration_ms": intel_duration
        })
    else:
        checks.append({
            "name": "Reputation & Threat Intelligence",
            "category": "Threat Intelligence",
            "status": "unavailable",
            "description": "Cross-references submitted URL against active threat intelligence databases.",
            "details": threat_intel["notes"] if threat_intel else "Threat intelligence check unavailable.",
            "duration_ms": intel_duration
        })

    # Phase 7: Deterministic Risk Classification & Score
    has_severe_heuristics = (
        components["has_userinfo"] 
        or (impersonated_brand is not None and threat_points >= 35.0)
        or (components["has_punycode"] and threat_points >= 30.0)
    )

    if is_intel_match:
        classification = "High Risk"
        risk_score = min(max(round(threat_points, 1), 60.0), 100.0)
    elif has_severe_heuristics:
        classification = "High Risk" if threat_points >= 50.0 else "Suspicious"
        risk_score = min(max(round(threat_points, 1), 0.0), 100.0)
    elif is_server_unreachable and threat_points < 30.0:
        # Host could not be reached, and no severe structural phishing signals exist -> Unknown
        classification = "Unknown"
        risk_score = 0.0
        findings.append(
            f"Destination server was unreachable or did not respond within the {deadline}s deadline ({probe_res['error_note'] if probe_res else 'timeout'}). "
            f"Insufficient technical evidence to evaluate legitimacy."
        )
    elif threat_points >= 40.0:
        classification = "High Risk"
        risk_score = min(max(round(threat_points, 1), 0.0), 100.0)
    elif threat_points >= 15.0:
        classification = "Suspicious"
        risk_score = min(max(round(threat_points, 1), 0.0), 100.0)
    else:
        classification = "Low Risk"
        risk_score = min(max(round(threat_points, 1), 0.0), 100.0)

    # Actionable safety recommendations
    recommendations: List[str] = []
    if classification == "High Risk":
        recommendations.append("Do NOT visit this link or enter passwords, phone numbers, or credit card information.")
        recommendations.append("If this link was received via email or SMS, mark it as phishing or spam in your client.")
        recommendations.append("If you have already entered credentials on this website, change your passwords immediately.")
    elif classification == "Suspicious":
        recommendations.append("Exercise heightened caution before navigating to or interacting with this website.")
        recommendations.append("Verify the website's authenticity through an independent search or bookmarks.")
        recommendations.append("Do not download files or authorize browser notification permissions.")
    elif classification == "Unknown":
        recommendations.append("The target website could not be contacted or evaluated definitively.")
        recommendations.append("If this destination should be online, check your network connectivity or try again later.")
        recommendations.append("Never submit passwords or sensitive data to unverified destinations.")
    else:
        recommendations.append("No prominent phishing or technical evasion indicators detected by automated scanning.")
        recommendations.append("Always verify the exact domain name before submitting sensitive banking or account credentials.")
        recommendations.append("Notice: Automated scanners cannot guarantee a website is completely free from emerging threats.")

    scan_duration_ms = round((time.perf_counter() - t_start) * 1000, 1)

    return {
        "url": raw_url,
        "normalized_url": normalized_url,
        "classification": classification,
        "risk_score": risk_score,
        "checks": checks,
        "findings": findings,
        "recommendations": recommendations,
        "scan_timestamp": scan_timestamp,
        "domain_info": structure_res["domain_info"],
        "https_info": {
            "is_https": is_https,
            "cert_valid": tls_info.get("valid") if tls_info else None,
            "issuer": tls_info.get("issuer") if tls_info else None,
            "subject": tls_info.get("subject") if tls_info else None,
            "expires": tls_info.get("expires") if tls_info else None
        },
        "redirect_info": {
            "redirect_count": redirect_count,
            "final_destination": final_dest,
            "chain": probe_res.get("redirect_chain", []) if probe_res else []
        },
        "threat_intel_info": threat_intel or {
            "configured": False,
            "checked": False,
            "matched": False,
            "notes": "Threat intelligence check unavailable."
        },
        "resolved_ip": primary_ip,
        "scan_duration_ms": scan_duration_ms,
        "disclaimer": "Automated security checks evaluate observed technical indicators and heuristics. They cannot guarantee that a website is free from fraud, social engineering, or emerging threats."
    }
