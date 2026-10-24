"""
ScamShield AI — Suspicious URL & Website Scanner Service
Provides deep URL structure analysis, SSRF-safe network probing, TLS inspection,
redirect tracking, heuristic indicator detection, and deterministic risk scoring.
"""

import ipaddress
import logging
import os
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlsplit, urlunsplit, parse_qs

logger = logging.getLogger("scamshield.url_scanner")

# -----------------------------------------------------------------------------
# CONSTANTS & SECURITY CONFIGURATION
# -----------------------------------------------------------------------------

ALLOWED_SCHEMES = {"http", "https"}
MAX_REDIRECTS = 5
SOCKET_CONNECT_TIMEOUT_SECONDS = 3.0
READ_TIMEOUT_SECONDS = 4.0
MAX_RESPONSE_BYTES = 65536  # 64 KB limit to prevent resource exhaustion
MAX_URL_LENGTH = 2048

# Common multi-part public suffixes to identify registered domain accurately
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

# Known URL shortener domains (informational warning, not definitive proof of fraud)
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "mcaf.ee", "rebrand.ly", "cutt.ly", "tiny.cc",
    "shorturl.at", "soo.gd", "s.id", "trib.al", "linktr.ee", "rb.gy", "qr.ae"
}

# High-profile brand names commonly impersonated in phishing lures
TARGETED_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "telegram", "bankofamerica", "chase", "wellsfargo",
    "citibank", "capitalone", "hsbc", "barclays", "lloyds", "santander",
    "binance", "coinbase", "metamask", "kraken", "trustwallet", "crypto",
    "usps", "fedex", "ups", "dhl", "royalmail", "auspost",
    "irs", "hmrc", "sbi", "hdfc", "icici", "axisbank", "paytm", "phonepe"
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
    # 1. Explicit check against cloud metadata IPs
    if ip_str.lower() in CLOUD_METADATA_IPS:
        return True, f"Target IP {ip_str} is a protected cloud metadata service."

    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"Invalid IP address representation: {ip_str}"

    # Handle IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:192.168.1.1)
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

    # Additional IPv4 carrier-grade NAT check (100.64.0.0/10)
    if isinstance(ip, ipaddress.IPv4Address):
        cgnat = ipaddress.ip_network("100.64.0.0/10")
        if ip in cgnat:
            return True, f"Target IP {ip} is within carrier-grade NAT / metadata address space."

    return False, ""


def resolve_and_validate_hostname(hostname: str) -> List[str]:
    """
    Resolves hostname to IP addresses and verifies that NONE of the resolved IPs
    are prohibited internal/private/loopback/cloud-metadata addresses.
    Returns the list of valid public IP strings.
    Raises SsrfBlockError if hostname is invalid or resolves to prohibited addresses.
    """
    clean_host = hostname.strip().lower().rstrip(".")
    if not clean_host:
        raise SsrfBlockError("Empty hostname is invalid.")

    # Check known metadata hostnames
    if clean_host in CLOUD_METADATA_HOSTNAMES or clean_host.endswith(".metadata.google.internal"):
        raise SsrfBlockError(f"Access to cloud metadata host '{hostname}' is blocked.")

    # Check localhost variations
    if clean_host == "localhost" or clean_host.endswith(".localhost") or clean_host.endswith(".local") or clean_host.endswith(".internal"):
        raise SsrfBlockError(f"Access to local or internal host '{hostname}' is blocked.")

    # If the hostname is already an IP address literal
    try:
        # Test if it parses directly as IP
        prohibited, reason = is_ip_address_prohibited(clean_host.strip("[]"))
        if prohibited:
            raise SsrfBlockError(f"Prohibited destination: {reason}")
        return [clean_host.strip("[]")]
    except ValueError:
        pass  # Not an IP literal, proceed to DNS resolution

    try:
        # Resolve both IPv4 and IPv6 addresses
        addr_info = socket.getaddrinfo(clean_host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
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

    # Validate EVERY resolved IP address
    for ip in resolved_ips:
        prohibited, reason = is_ip_address_prohibited(ip)
        if prohibited:
            raise SsrfBlockError(f"DNS resolution for '{hostname}' resolved to prohibited address ({ip}): {reason}")

    return resolved_ips


# -----------------------------------------------------------------------------
# DOMAIN & PUBLIC SUFFIX EXTRACTION
# -----------------------------------------------------------------------------

def extract_registered_domain(hostname: str) -> Tuple[str, str, str]:
    """
    Extracts (subdomain, registered_domain, tld) from a hostname using
    known multi-part public suffixes and standard single-part TLD logic.
    For example:
      'paypal.verification.bad.com' -> ('paypal.verification', 'bad.com', 'com')
      'login.service.co.uk'        -> ('login', 'service.co.uk', 'co.uk')
      '192.168.1.1'                -> ('', '192.168.1.1', '')
    """
    clean_host = hostname.strip().lower().rstrip(".")
    if not clean_host:
        return "", "", ""

    # Check if host is an IP address
    try:
        ipaddress.ip_address(clean_host.strip("[]"))
        return "", clean_host, ""
    except ValueError:
        pass

    parts = clean_host.split(".")
    if len(parts) <= 1:
        return "", clean_host, ""

    # Check for multi-part TLD (e.g., co.uk, com.au)
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

    # Check for illegal control characters
    if any(ord(c) < 32 or ord(c) == 127 for c in clean_url):
        raise ValueError("URL contains prohibited control characters.")

    # Ensure URL starts with a scheme; if user supplied 'example.com', default to https://
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

    # Use urlsplit for rigorous dissection
    try:
        parts = urlsplit(clean_url)
    except Exception as e:
        raise ValueError(f"Unable to parse URL structure: {str(e)}")

    if not parts.netloc:
        raise ValueError("URL is missing a valid destination hostname or authority.")

    # Detect deceptive '@' userinfo
    has_userinfo = "@" in parts.netloc
    userinfo = ""
    netloc_without_userinfo = parts.netloc
    if has_userinfo:
        userinfo, netloc_without_userinfo = parts.netloc.split("@", 1)

    # Extract host and optional port
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

    # Normalize IDN / Punycode
    punycode_host = host
    unicode_host = host
    has_punycode = False
    try:
        # Encode to punycode if needed
        punycode_host = host.encode("idna").decode("ascii")
        # Decode from punycode for unicode representation
        unicode_host = host.encode("ascii").decode("idna")
        if punycode_host.startswith("xn--") or ".xn--" in punycode_host:
            has_punycode = True
    except Exception:
        # Fall back gracefully if IDN decode fails
        pass

    # Normalize path
    path = parts.path or "/"

    # Reconstruct normalized URL safely without deceptive userinfo in authority
    netloc_normalized = punycode_host
    if port:
        # Only include non-standard ports
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
    Performs deterministic heuristic inspections on the URL structure:
    - Punycode & IDN obfuscation
    - Deceptive '@' credentials
    - IP-address hostname
    - Excessive subdomains and dots
    - Registered domain & TLD validation
    - URL length & suspicious encoding
    - Known URL shortener detection
    - Targeted brand name impersonation / spoofing
    """
    findings: List[str] = []
    checks: List[Dict[str, Any]] = []
    warnings_count = 0
    threat_points = 0.0

    host = components["punycode_host"]
    unicode_host = components["unicode_host"]
    path = components["path"]
    query = components["query"]

    # 1. Check Deceptive '@' Symbol
    if components["has_userinfo"]:
        userinfo_text = components["userinfo"]
        findings.append(
            f"Deceptive userinfo '@' symbol detected. Browsers may misinterpret '{userinfo_text}' "
            f"as authentication credentials while actually navigating to '{host}'."
        )
        checks.append({
            "name": "Deceptive Userinfo (@) Check",
            "category": "Structure",
            "status": "fail",
            "description": "Checks if the URL embeds fake domain names before an '@' delimiter.",
            "details": f"Detected embedded userinfo '{userinfo_text}' preceding destination '{host}'."
        })
        threat_points += 35.0
        warnings_count += 1
    else:
        checks.append({
            "name": "Deceptive Userinfo (@) Check",
            "category": "Structure",
            "status": "pass",
            "description": "Checks if the URL embeds fake domain names before an '@' delimiter.",
            "details": "No misleading userinfo or '@' delimiter found in URL authority."
        })

    # 2. Check IP Address Hostname
    is_ip_host = False
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip_host = True
    except ValueError:
        is_ip_host = False

    if is_ip_host:
        findings.append(
            f"Destination host is a raw IP address ({host}) rather than a registered domain name. "
            "Legitimate organizations rarely use raw IP addresses for public websites."
        )
        checks.append({
            "name": "Host Identity Format",
            "category": "Domain",
            "status": "warning",
            "description": "Verifies whether the host uses a standard domain name or raw numeric IP.",
            "details": f"Raw IP address host detected: {host}"
        })
        threat_points += 25.0
        warnings_count += 1
    else:
        checks.append({
            "name": "Host Identity Format",
            "category": "Domain",
            "status": "pass",
            "description": "Verifies whether the host uses a standard domain name or raw numeric IP.",
            "details": f"Host uses domain format: {host}"
        })

    # 3. Check Internationalized Domain Names & Punycode
    if components["has_punycode"]:
        findings.append(
            f"Internationalized Domain Name (Punycode: {host}) detected (Unicode: '{unicode_host}'). "
            "Attackers frequently use homoglyphs/lookalike characters to spoof legitimate brands."
        )
        checks.append({
            "name": "Punycode & Homoglyph Inspection",
            "category": "Domain",
            "status": "warning",
            "description": "Detects internationalized domain names (IDN) and lookalike characters.",
            "details": f"Punycode encoded domain: {host} (Displays as '{unicode_host}')"
        })
        threat_points += 20.0
        warnings_count += 1
    else:
        checks.append({
            "name": "Punycode & Homoglyph Inspection",
            "category": "Domain",
            "status": "pass",
            "description": "Detects internationalized domain names (IDN) and lookalike characters.",
            "details": "Standard ASCII domain labels; no Punycode ('xn--') detected."
        })

    # 4. Registered Domain & Subdomains
    subdomain, registered_domain, tld = extract_registered_domain(host)
    subdomain_count = len(subdomain.split(".")) if subdomain else 0

    if subdomain_count >= 3:
        findings.append(
            f"Excessive subdomain depth ({subdomain_count} levels: '{subdomain}'). "
            "Phishing kits often stack subdomains to mimic legitimate company structures."
        )
        checks.append({
            "name": "Subdomain Hierarchy Analysis",
            "category": "Domain",
            "status": "warning",
            "description": "Evaluates subdomain depth and complexity.",
            "details": f"Subdomain: '{subdomain}' on registered domain '{registered_domain}'"
        })
        threat_points += 15.0
        warnings_count += 1
    else:
        checks.append({
            "name": "Subdomain Hierarchy Analysis",
            "category": "Domain",
            "status": "pass",
            "description": "Evaluates subdomain depth and complexity.",
            "details": f"Registered domain: '{registered_domain}' (subdomain: '{subdomain or 'none'}')"
        })

    # 5. URL Shortener Detection (Informational Warning, NOT proof of scam)
    is_shortener = registered_domain.lower() in URL_SHORTENERS or host.lower() in URL_SHORTENERS
    if is_shortener:
        findings.append(
            f"Known URL shortener service ({registered_domain}) detected. "
            "Shortened links obscure the final landing page destination. Proceed with caution."
        )
        checks.append({
            "name": "URL Shortener Detection",
            "category": "Domain",
            "status": "info",
            "description": "Identifies link-shortening services that conceal the destination.",
            "details": f"Domain matches known URL shortening service: {registered_domain}"
        })
        threat_points += 10.0
    else:
        checks.append({
            "name": "URL Shortener Detection",
            "category": "Domain",
            "status": "pass",
            "description": "Identifies link-shortening services that conceal the destination.",
            "details": "Destination does not appear to be a known URL shortener service."
        })

    # 6. Brand Spoofing / Impersonation Check in Subdomain or Path
    impersonated_brand = None
    for brand in TARGETED_BRANDS:
        # Check if brand appears in subdomain or path, but registered domain is NOT that brand
        reg_domain_label = registered_domain.split(".")[0] if "." in registered_domain else registered_domain
        if reg_domain_label != brand:
            # Check if brand is in subdomain or path
            if (subdomain and brand in subdomain) or (brand in path.lower()):
                impersonated_brand = brand
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
            "details": f"Keyword '{impersonated_brand}' found on unrelated domain '{registered_domain}'."
        })
        threat_points += 30.0
        warnings_count += 1
    else:
        checks.append({
            "name": "Brand Impersonation & Typosquatting",
            "category": "Heuristics",
            "status": "pass",
            "description": "Checks if prominent brand names are embedded in unassociated domains.",
            "details": "No high-risk brand impersonation patterns detected in subdomain/path."
        })

    # 7. URL Length and Suspicious Obfuscation
    url_len = len(normalized_url)
    if url_len > 150:
        findings.append(f"Unusually long URL ({url_len} characters). Long URLs may conceal suspicious query parameters.")
        checks.append({
            "name": "URL Length & Encoding Obfuscation",
            "category": "Structure",
            "status": "info",
            "description": "Inspects URL length and potential parameter padding.",
            "details": f"Length: {url_len} characters."
        })
        threat_points += 5.0
    elif "%25" in raw_url:
        findings.append("Double percent-encoding (%25) detected in URL. May indicate evasion techniques.")
        checks.append({
            "name": "URL Length & Encoding Obfuscation",
            "category": "Structure",
            "status": "warning",
            "description": "Inspects URL length and potential parameter padding.",
            "details": "Double percent-encoding detected in URL parameters."
        })
        threat_points += 15.0
        warnings_count += 1
    else:
        checks.append({
            "name": "URL Length & Encoding Obfuscation",
            "category": "Structure",
            "status": "pass",
            "description": "Inspects URL length and potential parameter padding.",
            "details": f"URL length is within standard parameters ({url_len} chars)."
        })

    return {
        "findings": findings,
        "checks": checks,
        "threat_points": threat_points,
        "warnings_count": warnings_count,
        "domain_info": {
            "host": host,
            "unicode_host": unicode_host,
            "subdomain": subdomain,
            "registered_domain": registered_domain,
            "tld": tld,
            "is_ip_host": is_ip_host,
            "has_punycode": components["has_punycode"],
            "is_shortener": is_shortener
        }
    }


# -----------------------------------------------------------------------------
# SAFE TLS & CERTIFICATE INSPECTION (PHASE 3.B)
# -----------------------------------------------------------------------------

def inspect_tls_certificate(hostname: str, port: int = 443, target_ip: Optional[str] = None) -> Dict[str, Any]:
    """
    Safely inspects the TLS certificate of an HTTPS host.
    Pre-conditions: The hostname and target_ip must already be validated against SSRF!
    Never treats HTTPS as proof that a website is legitimate.
    """
    cert_info: Dict[str, Any] = {
        "inspected": False,
        "valid": False,
        "issuer": None,
        "subject": None,
        "expires": None,
        "san_domains": [],
        "notes": ""
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    # Connect to target
    connect_host = target_ip if target_ip else hostname
    try:
        with socket.create_connection((connect_host, port), timeout=SOCKET_CONNECT_TIMEOUT_SECONDS) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    cert_info["notes"] = "Server presented no TLS certificate."
                    return cert_info

                cert_info["inspected"] = True
                cert_info["valid"] = True

                # Extract Issuer
                issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                cert_info["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown Issuer"

                # Extract Subject
                subject_dict = dict(x[0] for x in cert.get("subject", ()))
                cert_info["subject"] = subject_dict.get("commonName") or "Unknown Subject"

                # Extract Expiry Date
                cert_info["expires"] = cert.get("notAfter")

                # Extract SANs
                san_list = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
                cert_info["san_domains"] = san_list[:10]  # Cap at first 10
                cert_info["notes"] = f"Valid TLS certificate issued by {cert_info['issuer']}."

    except ssl.SSLCertVerificationError as cert_err:
        cert_info["inspected"] = True
        cert_info["valid"] = False
        cert_info["notes"] = f"Certificate verification failed: {cert_err.verify_message or str(cert_err)}"
    except socket.timeout:
        cert_info["inspected"] = False
        cert_info["valid"] = False
        cert_info["notes"] = "Connection timed out during TLS handshake."
    except Exception as exc:
        cert_info["inspected"] = False
        cert_info["valid"] = False
        cert_info["notes"] = f"TLS inspection unavailable ({type(exc).__name__})."

    return cert_info


# -----------------------------------------------------------------------------
# CONTROLLED REDIRECT & LIVE PROBE (PHASE 3.D & PHASE 4)
# -----------------------------------------------------------------------------

def probe_url_and_follow_redirects(
    initial_url: str,
    components: Dict[str, Any],
    max_redirects: int = MAX_REDIRECTS
) -> Dict[str, Any]:
    """
    Safely executes controlled server-side redirect inspection:
    - Re-validates DNS and checks for SSRF at EVERY redirect step.
    - Limits response download size (max 64 KB).
    - Enforces strict socket connection & read timeouts.
    - Captures redirect chain and HTTP status codes.
    - Never executes JavaScript or renders remote HTML.
    """
    import urllib.request
    from urllib.error import HTTPError, URLError

    redirect_chain: List[Dict[str, Any]] = []
    current_url = initial_url
    final_destination = initial_url
    status_code = None
    response_headers = {}
    content_type = ""
    error_note = None

    # We manually handle redirects to strictly enforce SSRF validation at every hop
    class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None  # Prevent automatic redirection

    opener = urllib.request.build_opener(NoRedirectHandler)
    # Safe user agent that does not impersonate specific users or leak credentials
    opener.addheaders = [
        ("User-Agent", "ScamShieldAI-UrlScanner/1.0 (+https://project3-backend-fzlv.onrender.com)"),
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    ]

    for hop in range(max_redirects + 1):
        # 1. Parse current hop destination
        try:
            norm_hop, hop_components = normalize_and_validate_url(current_url)
        except Exception as e:
            error_note = f"Redirect target rejected: {str(e)}"
            break

        # 2. SSRF check on hop host
        try:
            resolved_ips = resolve_and_validate_hostname(hop_components["punycode_host"])
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

        # 3. Make the controlled network request
        req = urllib.request.Request(norm_hop, headers={
            "User-Agent": "ScamShieldAI-UrlScanner/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        })

        try:
            # We open connection with strict timeout
            with opener.open(req, timeout=SOCKET_CONNECT_TIMEOUT_SECONDS + READ_TIMEOUT_SECONDS) as resp:
                status_code = resp.status
                headers_dict = dict(resp.headers.items())
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
                # Reached terminal destination
                break

        except HTTPError as http_err:
            status_code = http_err.code
            content_type = http_err.headers.get_content_type() if http_err.headers else ""

            # Check for redirect status codes (301, 302, 303, 307, 308)
            if status_code in (301, 302, 303, 307, 308) and "Location" in http_err.headers:
                location = http_err.headers["Location"]
                redirect_chain.append({
                    "hop": hop,
                    "url": norm_hop,
                    "status_code": status_code,
                    "location": location
                })
                # Resolve relative redirects
                from urllib.parse import urljoin
                next_url = urljoin(norm_hop, location)

                # Check if we hit redirect loop
                if any(r.get("url") == next_url for r in redirect_chain):
                    error_note = f"Redirect loop detected at '{next_url}'."
                    break

                current_url = next_url
                final_destination = next_url
                continue
            else:
                # Terminal HTTP response with error code (e.g. 403, 404, 500)
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

    return {
        "status_code": status_code,
        "redirect_count": len(redirect_chain) - 1 if len(redirect_chain) > 1 else 0,
        "redirect_chain": redirect_chain,
        "final_destination": final_destination,
        "error_note": error_note,
        "content_type": content_type
    }


# -----------------------------------------------------------------------------
# THREAT INTELLIGENCE CONNECTOR (PHASE 3.C)
# -----------------------------------------------------------------------------

def check_threat_intelligence(url: str) -> Dict[str, Any]:
    """
    Checks threat intelligence feeds ONLY if an explicit API key is configured.
    If no key is configured, transparently reports that live reputation check
    was not performed. Never invents fake matches!
    """
    gsb_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not gsb_key and not vt_key:
        return {
            "configured": False,
            "provider": "None configured",
            "checked": False,
            "matched": False,
            "threat_type": None,
            "notes": "No external threat-intelligence API key (e.g. Google Safe Browsing or VirusTotal) configured on backend. Live reputation database check was skipped."
        }

    # Safe Browsing check if key is present
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
            with httpx.Client(timeout=4.0) as client:
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
                            "notes": f"Flagged by Google Safe Browsing as {t_type}."
                        }
                    return {
                        "configured": True,
                        "provider": "Google Safe Browsing v4",
                        "checked": True,
                        "matched": False,
                        "threat_type": None,
                        "notes": "No active threat matches found in Google Safe Browsing database."
                    }
        except Exception as e:
            logger.warning(f"Google Safe Browsing check failed: {e}")
            return {
                "configured": True,
                "provider": "Google Safe Browsing v4",
                "checked": False,
                "matched": False,
                "threat_type": None,
                "notes": f"Threat intelligence request failed: {str(e)}"
            }

    return {
        "configured": False,
        "provider": "None configured",
        "checked": False,
        "matched": False,
        "threat_type": None,
        "notes": "Threat intelligence provider configured but inactive."
    }


# -----------------------------------------------------------------------------
# MAIN COMPREHENSIVE SCANNER PIPELINE
# -----------------------------------------------------------------------------

def scan_url(raw_url: str) -> Dict[str, Any]:
    """
    Executes complete multi-phase URL inspection:
    1. Normalization & format validation
    2. SSRF defense validation & DNS resolution
    3. Heuristic structure, domain, & brand impersonation analysis
    4. HTTPS and TLS certificate inspection (with explicit non-guarantee)
    5. Controlled server-side redirect analysis
    6. Threat intelligence lookup (if configured)
    7. Deterministic risk assessment and safety recommendations
    """
    scan_timestamp = datetime.now(timezone.utc)

    # Phase 1: Normalize & Validate URL
    normalized_url, components = normalize_and_validate_url(raw_url)

    # Phase 2: SSRF Pre-flight DNS validation
    # This prevents scanning private networks or cloud metadata
    try:
        resolved_ips = resolve_and_validate_hostname(components["punycode_host"])
    except SsrfBlockError as ssrf_err:
        raise ssrf_err
    except ValueError as val_err:
        raise val_err

    primary_ip = resolved_ips[0] if resolved_ips else None

    # Phase 3: URL Structure & Heuristic Analysis
    structure_res = analyze_url_structure(raw_url, normalized_url, components)
    findings = structure_res["findings"]
    checks = structure_res["checks"]
    threat_points = structure_res["threat_points"]

    # Phase 4: HTTPS and TLS Certificate Inspection
    is_https = components["scheme"] == "https"
    tls_info = None

    if is_https:
        tls_info = inspect_tls_certificate(components["punycode_host"], components["port"], primary_ip)
        if tls_info["inspected"] and tls_info["valid"]:
            checks.append({
                "name": "HTTPS & TLS Security",
                "category": "Encryption",
                "status": "pass",
                "description": "Verifies valid SSL/TLS certificate configuration.",
                "details": f"Valid certificate presented by {tls_info['issuer']}. (Notice: HTTPS encrypts traffic but does NOT guarantee website authenticity)."
            })
        elif tls_info["inspected"] and not tls_info["valid"]:
            findings.append(f"Invalid or self-signed TLS certificate: {tls_info['notes']}")
            checks.append({
                "name": "HTTPS & TLS Security",
                "category": "Encryption",
                "status": "fail",
                "description": "Verifies valid SSL/TLS certificate configuration.",
                "details": tls_info["notes"]
            })
            threat_points += 30.0
        else:
            checks.append({
                "name": "HTTPS & TLS Security",
                "category": "Encryption",
                "status": "unavailable",
                "description": "Verifies valid SSL/TLS certificate configuration.",
                "details": f"TLS inspection could not be completed ({tls_info['notes']})."
            })
    else:
        findings.append("URL uses unencrypted plain HTTP protocol. Transmitted credentials or forms can be intercepted in transit.")
        checks.append({
            "name": "HTTPS & TLS Security",
            "category": "Encryption",
            "status": "warning",
            "description": "Verifies whether connection uses encrypted HTTPS protocol.",
            "details": "Plain HTTP protocol detected; communications are not encrypted."
        })
        threat_points += 15.0

    # Phase 5: Controlled Server-Side Redirect Inspection
    probe_res = probe_url_and_follow_redirects(normalized_url, components)
    redirect_count = probe_res["redirect_count"]
    final_dest = probe_res["final_destination"]

    if redirect_count > 0:
        findings.append(
            f"URL triggered {redirect_count} redirect(s), landing at '{final_dest}'."
        )
        checks.append({
            "name": "Redirect Destination Tracking",
            "category": "Network",
            "status": "info" if redirect_count <= 2 else "warning",
            "description": "Inspects server-side redirect hops to identify final landing page.",
            "details": f"{redirect_count} redirect(s) followed. Final landing page: '{final_dest}'"
        })
        if redirect_count >= 3:
            threat_points += 10.0
    else:
        checks.append({
            "name": "Redirect Destination Tracking",
            "category": "Network",
            "status": "pass",
            "description": "Inspects server-side redirect hops to identify final landing page.",
            "details": "No external redirects encountered."
        })

    if probe_res["error_note"]:
        checks.append({
            "name": "Server Reachability",
            "category": "Network",
            "status": "unavailable",
            "description": "Checks if the remote web server responds to HTTP requests.",
            "details": probe_res["error_note"]
        })
    else:
        checks.append({
            "name": "Server Reachability",
            "category": "Network",
            "status": "pass",
            "description": "Checks if the remote web server responds to HTTP requests.",
            "details": f"Server responded with HTTP {probe_res['status_code']}."
        })

    # Phase 6: Threat Intelligence Check
    threat_intel = check_threat_intelligence(normalized_url)
    if threat_intel["matched"]:
        threat_points += 60.0
        findings.append(f"Threat Intelligence Alert: URL matches known malicious database ({threat_intel['threat_type']}).")
        checks.append({
            "name": "Reputation & Threat Intelligence",
            "category": "Threat Intelligence",
            "status": "fail",
            "description": "Cross-references submitted URL against active threat intelligence databases.",
            "details": threat_intel["notes"]
        })
    elif threat_intel["checked"]:
        checks.append({
            "name": "Reputation & Threat Intelligence",
            "category": "Threat Intelligence",
            "status": "pass",
            "description": "Cross-references submitted URL against active threat intelligence databases.",
            "details": threat_intel["notes"]
        })
    else:
        checks.append({
            "name": "Reputation & Threat Intelligence",
            "category": "Threat Intelligence",
            "status": "unavailable",
            "description": "Cross-references submitted URL against active threat intelligence databases.",
            "details": threat_intel["notes"]
        })

    # Phase 7: Deterministic Risk Classification & Score
    # Risk points bounded between 0 and 100
    risk_score = min(max(round(threat_points, 1), 0.0), 100.0)

    if risk_score >= 50.0 or threat_intel.get("matched"):
        classification = "High Risk"
    elif risk_score >= 20.0:
        classification = "Suspicious"
    elif probe_res["error_note"] and not findings:
        classification = "Unknown"
    else:
        classification = "Low Risk"

    # Recommendations based on classification and findings
    recommendations: List[str] = []
    if classification == "High Risk":
        recommendations.append("Do NOT visit this link or enter passwords, phone numbers, or credit card information.")
        recommendations.append("If this link was received via email or SMS, mark it as phishing or spam in your client.")
        recommendations.append("If you have already entered credentials on this website, change your passwords immediately.")
    elif classification == "Suspicious":
        recommendations.append("Exercise extreme caution before navigating to this website.")
        recommendations.append("Verify the website's authenticity through an independent search or bookmarks.")
        recommendations.append("Do not download files or authorize browser notification permissions.")
    else:
        recommendations.append("No immediate technical threats detected by automated heuristic scanning.")
        recommendations.append("Always verify the web address before submitting sensitive banking or account credentials.")
        recommendations.append("Remember: Automated scanners cannot guarantee a website is completely safe.")

    # Return structured scan object
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
            "chain": probe_res["redirect_chain"]
        },
        "threat_intel_info": threat_intel,
        "resolved_ip": primary_ip,
        "disclaimer": "Automated security checks evaluate observed technical indicators and heuristics. They cannot guarantee that a website is free from fraud, social engineering, or emerging threats."
    }
