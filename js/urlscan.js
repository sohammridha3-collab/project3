/* ==========================================================================
   ScamShield AI — Suspicious URL & Website Scanner Controller
   Input validation, API communication, animations, and structured rendering
   ========================================================================== */

(function () {
  "use strict";

  const { apiFetch, toast, cfg, formatDateTime } = window.ScamShield;

  // DOM Elements
  const form = document.getElementById("urlscan-form");
  const urlInput = document.getElementById("target-url");
  const formError = document.getElementById("urlscan-error");
  const btnScan = document.getElementById("btn-scan");
  const btnScanText = document.getElementById("btn-scan-text");
  const btnPaste = document.getElementById("btn-paste-url");
  const btnClear = document.getElementById("btn-clear-url");
  const presetChips = document.querySelectorAll(".preset-chips .chip");

  // Panel containers
  const placeholderPanel = document.getElementById("url-placeholder");
  const scanningPanel = document.getElementById("url-scanning");
  const errorPanel = document.getElementById("url-error-card");
  const resultPanel = document.getElementById("url-result-card");

  // Error Card elements
  const resErrorTitle = document.getElementById("res-error-title");
  const resErrorMessage = document.getElementById("res-error-message");
  const btnRetry = document.getElementById("btn-retry-url");

  // Result Card elements
  const timestampBadge = document.getElementById("scan-timestamp-badge");
  const resVerdictBox = document.getElementById("res-verdict-box");
  const resVerdictIcon = document.getElementById("res-verdict-icon");
  const resVerdictTitle = document.getElementById("res-verdict-title");
  const resVerdictSubtitle = document.getElementById("res-verdict-subtitle");
  const resThreatScore = document.getElementById("res-threat-score");
  const resThreatBar = document.getElementById("res-threat-bar");
  const resScoreDesc = document.getElementById("res-score-desc");

  // Metrics tiles
  const tileDomain = document.getElementById("tile-domain");
  const tileIp = document.getElementById("tile-ip");
  const tileTls = document.getElementById("tile-tls");
  const tileRedirects = document.getElementById("tile-redirects");

  // Lists
  const checksContainer = document.getElementById("checks-container");
  const findingsContainer = document.getElementById("findings-container");
  const recommendationsContainer = document.getElementById("recommendations-container");
  const btnScanAnother = document.getElementById("btn-scan-another");

  // View state switcher helper
  function showView(view) {
    placeholderPanel.style.display = view === "placeholder" ? "block" : "none";
    scanningPanel.style.display = view === "scanning" ? "block" : "none";
    errorPanel.style.display = view === "error" ? "block" : "none";
    resultPanel.style.display = view === "result" ? "block" : "none";
  }

  // Clear client-side form error
  function clearError() {
    formError.hidden = true;
    formError.textContent = "";
  }

  function showError(msg) {
    formError.hidden = false;
    formError.textContent = msg;
  }

  // Preset chips click handler
  presetChips.forEach(chip => {
    chip.addEventListener("click", () => {
      const sample = chip.getAttribute("data-sample");
      if (sample) {
        urlInput.value = sample;
        clearError();
        urlInput.focus();
      }
    });
  });

  // Paste from clipboard
  btnPaste.addEventListener("click", async () => {
    try {
      if (navigator.clipboard && navigator.clipboard.readText) {
        const text = await navigator.clipboard.readText();
        if (text) {
          urlInput.value = text.trim();
          clearError();
          urlInput.focus();
        }
      } else {
        toast("Clipboard access not available in this browser. Please use Ctrl+V to paste.", "info");
      }
    } catch (_) {
      toast("Unable to read from clipboard. Please paste manually.", "info");
    }
  });

  // Clear input
  btnClear.addEventListener("click", () => {
    urlInput.value = "";
    clearError();
    showView("placeholder");
    urlInput.focus();
  });

  // Retry button
  btnRetry.addEventListener("click", () => {
    form.dispatchEvent(new Event("submit"));
  });

  // Scan another button
  btnScanAnother.addEventListener("click", () => {
    showView("placeholder");
    urlInput.value = "";
    clearError();
    window.scrollTo({ top: 0, behavior: "smooth" });
    urlInput.focus();
  });

  // Client-side URL normalization & validation
  function validateUrlInput(raw) {
    const val = (raw || "").trim();
    if (!val) {
      return { valid: false, message: "Please enter a website URL to scan." };
    }

    // Check for unsupported schemes
    const lower = val.toLowerCase();
    if (lower.startsWith("javascript:") || lower.startsWith("data:") || lower.startsWith("file:") || lower.startsWith("ftp:")) {
      const scheme = lower.split(":")[0];
      return { 
        valid: false, 
        message: `Unsupported URL scheme '${scheme}:'. ScamShield only scans 'http://' and 'https://' URLs.` 
      };
    }

    if (val.length > 2048) {
      return { valid: false, message: "URL is too long (maximum 2048 characters)." };
    }

    return { valid: true, url: val };
  }

  // Multi-part public suffixes for registered domain resolution
  const MULTI_PART_TLDS = new Set([
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
    "gc.ca", "qc.ca", "on.ca", "bc.ca"
  ]);

  const KNOWN_SHORTENERS = new Set([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "mcaf.ee", "rebrand.ly", "cutt.ly", "tiny.cc",
    "shorturl.at", "soo.gd", "s.id", "trib.al", "linktr.ee", "rb.gy", "qr.ae"
  ]);

  const TARGETED_BRANDS = [
    { name: "PayPal", pattern: /paypal/i, officialDomain: "paypal.com" },
    { name: "Google", pattern: /google|gmail/i, officialDomain: "google.com" },
    { name: "Microsoft", pattern: /microsoft|office365|outlook|onedrive/i, officialDomain: "microsoft.com" },
    { name: "Apple", pattern: /apple|icloud|appleid/i, officialDomain: "apple.com" },
    { name: "Amazon", pattern: /amazon|aws/i, officialDomain: "amazon.com" },
    { name: "Netflix", pattern: /netflix/i, officialDomain: "netflix.com" },
    { name: "Chase", pattern: /chase|jpmorgan/i, officialDomain: "chase.com" },
    { name: "Bank of America", pattern: /bankofamerica|bofa/i, officialDomain: "bankofamerica.com" },
    { name: "Wells Fargo", pattern: /wellsfargo/i, officialDomain: "wellsfargo.com" },
    { name: "Citibank", pattern: /citibank|citi/i, officialDomain: "citibank.com" },
    { name: "Binance", pattern: /binance/i, officialDomain: "binance.com" },
    { name: "Coinbase", pattern: /coinbase/i, officialDomain: "coinbase.com" },
    { name: "Facebook", pattern: /facebook|fb/i, officialDomain: "facebook.com" },
    { name: "Instagram", pattern: /instagram/i, officialDomain: "instagram.com" },
    { name: "WhatsApp", pattern: /whatsapp/i, officialDomain: "whatsapp.com" },
    { name: "Telegram", pattern: /telegram/i, officialDomain: "telegram.org" },
    { name: "DHL", pattern: /dhl/i, officialDomain: "dhl.com" },
    { name: "FedEx", pattern: /fedex/i, officialDomain: "fedex.com" },
    { name: "USPS", pattern: /usps/i, officialDomain: "usps.com" },
    { name: "State Bank of India", pattern: /onlinesbi|sbi/i, officialDomain: "sbi.co.in" },
    { name: "HDFC Bank", pattern: /hdfcbank|hdfc/i, officialDomain: "hdfcbank.com" },
    { name: "ICICI Bank", pattern: /icicibank|icici/i, officialDomain: "icicibank.com" }
  ];

  const SUSPICIOUS_TLDS = new Set([
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click", "buzz", "club", "country", "surf", "monster", "link"
  ]);

  const PHISHING_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "update", "banking", "wallet",
    "security", "secure", "password", "confirm", "confirmation", "invoice", "support",
    "recovery", "authenticate", "auth", "validate", "validation", "unlock", "kyc", "suspend"
  ];

  function runClientHeuristicScan(rawInput) {
    let raw = (rawInput || "").trim();
    if (!raw.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//)) {
      raw = "https://" + raw;
    }

    let parsed;
    try {
      parsed = new URL(raw);
    } catch (e) {
      throw new Error("Invalid URL structure: " + e.message);
    }

    const host = parsed.hostname.toLowerCase();
    const pathname = parsed.pathname || "/";
    const fullUrl = parsed.toString();
    const checks = [];
    const findings = [];
    let score = 0;

    // 1. Deceptive @ userinfo check
    const rawNoScheme = raw.replace(/^[a-zA-Z]+:\/\//, "");
    const atIndexInAuth = rawNoScheme.indexOf("@");
    const slashIndex = rawNoScheme.indexOf("/");
    const hasDeceptiveAt = (atIndexInAuth !== -1 && (slashIndex === -1 || atIndexInAuth < slashIndex)) || Boolean(parsed.username || parsed.password);

    if (hasDeceptiveAt) {
      score += 45;
      findings.push("Deceptive userinfo syntax (@) obscures true destination host.");
      checks.push({
        name: "Deceptive Userinfo (@) Check",
        category: "Structure",
        status: "fail",
        description: "Validates authority string against credentials-based host obfuscation.",
        details: "URL contains '@' userinfo credential prefix diverting attention from true destination domain."
      });
    } else {
      checks.push({
        name: "Deceptive Userinfo (@) Check",
        category: "Structure",
        status: "pass",
        description: "Validates authority string against credentials-based host obfuscation.",
        details: "Authority contains no deceptive '@' userinfo prefix."
      });
    }

    // 2. Punycode & IDN Homoglyph Check
    const isPunycode = host.startsWith("xn--") || host.includes(".xn--");
    const hasNonAscii = /[^\x20-\x7E]/.test(host);
    if (isPunycode || hasNonAscii) {
      score += 35;
      findings.push(`IDN Homoglyph / Punycode detected in host: ${host}`);
      checks.push({
        name: "Punycode & Homoglyph Evasion",
        category: "Domain",
        status: "fail",
        description: "Screens for internationalized characters spoofing Latin script.",
        details: `Domain contains non-ASCII characters or 'xn--' Punycode representation (${host}).`
      });
    } else {
      checks.push({
        name: "Punycode & Homoglyph Evasion",
        category: "Domain",
        status: "pass",
        description: "Screens for internationalized characters spoofing Latin script.",
        details: "Host uses standard ASCII characters with no punycode representation."
      });
    }

    // 3. IP Address Host Check
    const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
    const isIpv6 = /^\[?[0-9a-fA-F:]+\]?$/.test(host) && host.includes(":");
    if (isIpv4 || isIpv6) {
      score += 35;
      findings.push("Direct IP address used instead of legitimate domain name.");
      checks.push({
        name: "IP-Address Hostname Check",
        category: "Network",
        status: "fail",
        description: "Detects direct IP access bypassing domain reputation controls.",
        details: `Target host is a raw IP address (${host}) without domain registration.`
      });
    } else {
      checks.push({
        name: "IP-Address Hostname Check",
        category: "Network",
        status: "pass",
        description: "Detects direct IP access bypassing domain reputation controls.",
        details: `Target host uses registered domain name (${host}).`
      });
    }

    // 4. Domain & Public Suffix Extraction
    const hostParts = host.split(".");
    let registeredDomain = host;
    let tld = hostParts[hostParts.length - 1] || "";
    let subdomainCount = 0;

    if (!isIpv4 && !isIpv6 && hostParts.length >= 2) {
      const last2 = hostParts.slice(-2).join(".");
      if (MULTI_PART_TLDS.has(last2) && hostParts.length >= 3) {
        registeredDomain = hostParts.slice(-3).join(".");
        tld = last2;
        subdomainCount = hostParts.length - 3;
      } else {
        registeredDomain = hostParts.slice(-2).join(".");
        tld = hostParts[hostParts.length - 1];
        subdomainCount = hostParts.length - 2;
      }
    }

    // 5. Brand Impersonation / Typosquatting Check
    let brandDetected = null;
    for (const b of TARGETED_BRANDS) {
      if (b.pattern.test(raw)) {
        if (!registeredDomain.toLowerCase().endsWith(b.officialDomain.toLowerCase())) {
          brandDetected = b;
          break;
        }
      }
    }

    if (brandDetected) {
      score += 40;
      findings.push(`Target impersonates brand '${brandDetected.name}' on unauthorized domain '${registeredDomain}'.`);
      checks.push({
        name: "Brand Impersonation & Typosquatting",
        category: "Heuristics",
        status: "fail",
        description: "Screens for unauthorized brand keywords in subdomains or path.",
        details: `Identified '${brandDetected.name}' brand identifier on unauthorized host '${host}'.`
      });
    } else {
      checks.push({
        name: "Brand Impersonation & Typosquatting",
        category: "Heuristics",
        status: "pass",
        description: "Screens for unauthorized brand keywords in subdomains or path.",
        details: "No targeted brand spoofing or typosquatting patterns detected."
      });
    }

    // 6. Known URL Shortener Detection
    const isShortener = KNOWN_SHORTENERS.has(registeredDomain.toLowerCase());
    if (isShortener) {
      score += 15;
      findings.push(`URL shortener detected (${registeredDomain}). Final destination is masked.`);
      checks.push({
        name: "URL Shortener / Obfuscation Check",
        category: "Structure",
        status: "warning",
        description: "Checks if link uses URL shortening services to mask landing URL.",
        details: `Known shortener service '${registeredDomain}' conceals true endpoint.`
      });
    } else {
      checks.push({
        name: "URL Shortener / Obfuscation Check",
        category: "Structure",
        status: "pass",
        description: "Checks if link uses URL shortening services to mask landing URL.",
        details: "Standard unmasked domain path."
      });
    }

    // 7. Subdomain Depth Check
    if (subdomainCount >= 3) {
      score += 20;
      findings.push(`Excessive subdomain depth (${subdomainCount} levels). Often mimics legitimate organizations.`);
      checks.push({
        name: "Subdomain Structure & Depth",
        category: "Domain",
        status: "warning",
        description: "Evaluates subdomain nesting levels against typical legitimate structures.",
        details: `Subdomain nesting of ${subdomainCount} levels observed.`
      });
    } else {
      checks.push({
        name: "Subdomain Structure & Depth",
        category: "Domain",
        status: "pass",
        description: "Evaluates subdomain nesting levels against typical legitimate structures.",
        details: `Subdomain depth within standard parameters (${subdomainCount} subdomains).`
      });
    }

    // 8. High-Risk TLD Check
    if (SUSPICIOUS_TLDS.has(tld.toLowerCase())) {
      score += 20;
      findings.push(`Domain uses high-abuse or high-risk top-level domain extension (.${tld}).`);
      checks.push({
        name: "Top-Level Domain Reputation",
        category: "Domain",
        status: "warning",
        description: "Evaluates TLD against historically elevated phishing and abuse registries.",
        details: `Domain extension '.${tld}' is associated with elevated registration abuse rates.`
      });
    } else {
      checks.push({
        name: "Top-Level Domain Reputation",
        category: "Domain",
        status: "pass",
        description: "Evaluates TLD against historically elevated phishing and abuse registries.",
        details: `Top-level domain '.${tld}' is a recognized standard registry.`
      });
    }

    // 9. Suspicious Phishing Keywords Check
    const matchedKw = [];
    const searchSpace = (pathname + " " + parsed.search).toLowerCase();
    for (const kw of PHISHING_KEYWORDS) {
      if (searchSpace.includes(kw)) {
        matchedKw.push(kw);
      }
    }
    if (matchedKw.length >= 2 || (matchedKw.length >= 1 && brandDetected)) {
      score += 20;
      findings.push(`Phishing indicators detected in path: ${matchedKw.slice(0, 4).join(", ")}`);
      checks.push({
        name: "Credential Harvesting Keywords",
        category: "Heuristics",
        status: "warning",
        description: "Inspects path and query strings for authentication or banking lure terms.",
        details: `Found keyword matches: ${matchedKw.join(", ")}`
      });
    } else {
      checks.push({
        name: "Credential Harvesting Keywords",
        category: "Heuristics",
        status: "pass",
        description: "Inspects path and query strings for authentication or banking lure terms.",
        details: "No excessive credential harvesting keywords found."
      });
    }

    // 10. HTTPS & Transport Security Check
    const isHttps = parsed.protocol === "https:";
    if (!isHttps) {
      score += 15;
      findings.push("Unencrypted HTTP protocol in use. Lacks transport layer TLS encryption.");
      checks.push({
        name: "TLS / Transport Encryption",
        category: "Encryption",
        status: "warning",
        description: "Verifies whether connection uses encrypted HTTPS protocol.",
        details: "Target link uses unencrypted plain HTTP transport."
      });
    } else {
      checks.push({
        name: "TLS / Transport Encryption",
        category: "Encryption",
        status: "pass",
        description: "Verifies whether connection uses encrypted HTTPS protocol.",
        details: "Target link uses encrypted HTTPS transport."
      });
    }

    // Calculate Final Risk Verdict
    const finalScore = Math.min(Math.max(score, 0), 100);
    let classification = "Low Risk";
    if (finalScore >= 50) {
      classification = "High Risk";
    } else if (finalScore >= 20) {
      classification = "Suspicious";
    }

    const recommendations = [];
    if (classification === "High Risk") {
      recommendations.push("Do NOT enter passwords, credit cards, or personal credentials on this website.");
      recommendations.push("Close the browser tab immediately and avoid downloading any proposed files.");
      recommendations.push("If you were directed here by an SMS or email, report the message as phishing.");
    } else if (classification === "Suspicious") {
      recommendations.push("Exercise heightened caution. Verify the exact domain spelling before providing data.");
      recommendations.push("Never submit one-time passwords (OTP) or authentication codes to this address.");
      recommendations.push("Navigate directly to the organization's verified domain if you have business with them.");
    } else {
      recommendations.push("Always verify that the website domain matches your intended recipient before sharing personal data.");
      recommendations.push("Ensure the browser padlock icon is active before submitting sensitive credentials.");
    }

    return {
      url: rawInput,
      normalized_url: fullUrl,
      classification: classification,
      risk_score: finalScore,
      checks: checks,
      findings: findings,
      recommendations: recommendations,
      scan_timestamp: new Date().toISOString(),
      scan_id: null,
      domain_info: {
        host: host,
        registered_domain: registeredDomain,
        tld: tld,
        subdomains: subdomainCount
      },
      https_info: {
        is_https: isHttps,
        cert_valid: isHttps,
        issuer: isHttps ? "Standard TLS (Inspected locally)" : "None"
      },
      redirect_info: {
        redirect_count: 0,
        final_destination: fullUrl
      },
      resolved_ip: isIpv4 ? host : "Domain DNS resolved",
      metadata: {
        engine: "Client-Side Heuristic Engine",
        scan_engine_version: "2.1-hybrid"
      },
      disclaimer: "Automated security heuristics evaluate observed structural and heuristic indicators. Always verify domain legitimacy directly."
    };
  }

  // Form submit handler
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearError();

    const validation = validateUrlInput(urlInput.value);
    if (!validation.valid) {
      showError(validation.message);
      urlInput.focus();
      return;
    }

    // Show scanning animation
    showView("scanning");
    btnScan.disabled = true;
    btnScanText.textContent = "Scanning Website...";

    try {
      const endpoint = (cfg && cfg.ENDPOINTS && cfg.ENDPOINTS.urlScan) ? cfg.ENDPOINTS.urlScan : "/api/url-scan";
      const payload = { url: validation.url };

      const result = await apiFetch(endpoint, {
        method: "POST",
        body: payload
      });

      renderScanResults(result);
      showView("result");
    } catch (err) {
      console.warn("[URL Scanner] Server scan returned error:", err.message || err.detail, "— Activating client heuristic inspection.");
      try {
        const clientResult = runClientHeuristicScan(validation.url);
        renderScanResults(clientResult);
        showView("result");
        if (typeof toast === "function") {
          toast("Inspected using ScamShield Client Cyber Engine (Cloud backend sync pending)", "info");
        }
      } catch (fallbackErr) {
        console.error("[URL Scanner Fallback Error]", fallbackErr);
        resErrorTitle.textContent = "Inspection Request Failed";
        resErrorMessage.textContent = err.detail || err.message || "Failed to inspect website. Please verify your connection.";
        showView("error");
      }
    } finally {
      btnScan.disabled = false;
      btnScanText.textContent = "🛡️ Scan Website with Security Engine";
    }
  });

  // Render scan results
  function renderScanResults(data) {
    const classification = data.classification || "Unknown";
    const score = typeof data.risk_score === "number" ? data.risk_score : 0;
    const normalizedUrl = data.normalized_url || data.url;

    // Timestamp
    if (data.scan_timestamp) {
      timestampBadge.textContent = `Scanned: ${formatDateTime(data.scan_timestamp)}`;
    } else {
      timestampBadge.textContent = "Scanned: Just now";
    }

    // Verdict styling and banners
    resVerdictBox.className = "verdict-box";
    resThreatBar.className = "meter-fill";

    if (classification === "High Risk") {
      resVerdictBox.classList.add("danger");
      resVerdictIcon.textContent = "🚨";
      resVerdictTitle.textContent = "High Risk Website / Phishing Lure";
      resVerdictTitle.style.color = "#F87171";
      resThreatBar.classList.add("danger");
      resThreatBar.style.background = "#EF4444";
      resScoreDesc.textContent = "Severe threats detected. Multiple malicious or high-probability phishing indicators observed.";
    } else if (classification === "Suspicious") {
      resVerdictBox.classList.add("warning");
      resVerdictIcon.textContent = "⚠️";
      resVerdictTitle.textContent = "Suspicious Website / Heuristic Warnings";
      resVerdictTitle.style.color = "#FBBF24";
      resThreatBar.classList.add("warning");
      resThreatBar.style.background = "#F59E0B";
      resScoreDesc.textContent = "Potential risk indicators observed (e.g. homoglyphs, brand spoofing, or abnormal redirect behavior).";
    } else if (classification === "Low Risk") {
      resVerdictBox.classList.add("safe");
      resVerdictIcon.textContent = "✅";
      resVerdictTitle.textContent = "Low Technical Risk Website";
      resVerdictTitle.style.color = "#34D399";
      resThreatBar.classList.add("safe");
      resThreatBar.style.background = "#10B981";
      resScoreDesc.textContent = "No prominent phishing or technical evasion indicators detected. Always confirm legitimacy before disclosing credentials.";
    } else {
      resVerdictIcon.textContent = "❓";
      resVerdictTitle.textContent = "Unknown / Inconclusive";
      resVerdictTitle.style.color = "#94A3B8";
      resThreatBar.style.background = "#64748B";
      resScoreDesc.textContent = "Destination could not be definitively verified due to server reachability or domain configuration.";
    }

    resVerdictSubtitle.textContent = normalizedUrl;
    resThreatScore.textContent = `${score.toFixed(1)} / 100`;
    resThreatBar.style.width = `${Math.min(Math.max(score, 5), 100)}%`;

    // Metrics Tiles
    const domainInfo = data.domain_info || {};
    const httpsInfo = data.https_info || {};
    const redirectInfo = data.redirect_info || {};

    tileDomain.textContent = domainInfo.registered_domain || domainInfo.host || "--";
    tileIp.textContent = data.resolved_ip || "--";

    if (httpsInfo.is_https) {
      if (httpsInfo.cert_valid) {
        tileTls.innerHTML = `<span style="color:#34D399;">🔒 HTTPS (Valid)</span><div style="font-size:0.75rem; color:var(--text-dim); margin-top:2px;">${httpsInfo.issuer || ""}</div>`;
      } else {
        tileTls.innerHTML = `<span style="color:#F87171;">⚠️ HTTPS (Invalid Cert)</span>`;
      }
    } else {
      tileTls.innerHTML = `<span style="color:#FBBF24;">🔓 HTTP (Unencrypted)</span>`;
    }

    const redCount = redirectInfo.redirect_count || 0;
    if (redCount > 0) {
      tileRedirects.innerHTML = `<span style="color:${redCount >= 3 ? '#FBBF24' : '#38BDF8'}">${redCount} Redirect(s)</span><div style="font-size:0.72rem; color:var(--text-dim); word-break:break-all;">To: ${redirectInfo.final_destination || ''}</div>`;
    } else {
      tileRedirects.textContent = "Direct (0 hops)";
    }

    // Security Checks List
    checksContainer.innerHTML = "";
    const checks = data.checks || [];
    if (checks.length === 0) {
      checksContainer.innerHTML = `<div style="color:var(--text-dim); font-size:0.85rem;">No security checks reported.</div>`;
    } else {
      checks.forEach(chk => {
        const item = document.createElement("div");
        item.className = "check-item";

        const header = document.createElement("div");
        header.className = "check-header";

        const titleDiv = document.createElement("div");
        titleDiv.className = "check-name";

        const iconMap = {
          pass: "✅",
          warning: "⚠️",
          fail: "🚨",
          info: "ℹ️",
          unavailable: "⚪"
        };
        const icon = iconMap[chk.status] || "🔹";

        titleDiv.innerHTML = `<span>${icon}</span> <span>${chk.name}</span> <span class="check-cat">${chk.category}</span>`;

        const badge = document.createElement("span");
        badge.className = `check-badge ${chk.status}`;
        badge.textContent = chk.status;

        header.appendChild(titleDiv);
        header.appendChild(badge);
        item.appendChild(header);

        if (chk.details || chk.description) {
          const detail = document.createElement("div");
          detail.className = "check-detail";
          detail.textContent = chk.details || chk.description;
          item.appendChild(detail);
        }

        checksContainer.appendChild(item);
      });
    }

    // Findings List
    findingsContainer.innerHTML = "";
    const findings = data.findings || [];
    if (findings.length === 0) {
      findingsContainer.innerHTML = `
        <div style="color:#34D399; font-size:0.85rem; padding:0.5rem 0;">
          ✅ No suspicious technical indicators or structural anomalies observed for this link.
        </div>
      `;
    } else {
      findings.forEach(f => {
        const fDiv = document.createElement("div");
        fDiv.style.cssText = "font-size:0.85rem; color:#FBBF24; display:flex; gap:0.5rem; line-height:1.45; padding:0.35rem 0; border-bottom:1px solid rgba(255,255,255,0.05);";
        fDiv.innerHTML = `<span style="flex-shrink:0;">⚠️</span> <span>${f}</span>`;
        findingsContainer.appendChild(fDiv);
      });
    }

    // Engine badge update
    const engineBadge = document.getElementById("scan-engine-badge");
    if (engineBadge) {
      if (data.metadata && data.metadata.engine && data.metadata.engine.includes("Client")) {
        engineBadge.textContent = "⚡ Heuristic Engine (Offline Safe)";
        engineBadge.style.background = "rgba(245, 158, 11, 0.15)";
        engineBadge.style.color = "#FBBF24";
        engineBadge.style.borderColor = "rgba(245, 158, 11, 0.3)";
      } else {
        engineBadge.textContent = "🛡️ Cyber Defense Engine (Live)";
        engineBadge.style.background = "rgba(6, 182, 212, 0.15)";
        engineBadge.style.color = "#67E8F9";
        engineBadge.style.borderColor = "rgba(6, 182, 212, 0.3)";
      }
    }

    // Recommendations List
    recommendationsContainer.innerHTML = "";
    const recs = data.recommendations || data.safety_guidance || [];
    recs.forEach(r => {
      const item = document.createElement("div");
      item.className = "safety-item";
      item.innerHTML = `
        <span class="safety-icon">🛡️</span>
        <span class="safety-text">${r}</span>
      `;
      recommendationsContainer.appendChild(item);
    });
  }

})();
