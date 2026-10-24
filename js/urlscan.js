/* ==========================================================================
   ScamShield AI — Suspicious URL & Website Scanner Controller
   Fast, accurate, resilient UI controller with cold-start detection,
   per-check execution timings, and verified backend reporting.
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
  const scanningStatusText = document.getElementById("scanning-status-text");

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

  // ML Detection elements
  const fastScanToggle = document.getElementById("fast-scan-toggle");
  const mlVerdictBanner = document.getElementById("ml-verdict-banner");
  const mlVerdictText = document.getElementById("ml-verdict-text");
  const mlProbBadge = document.getElementById("ml-prob-badge");
  const mlDurationBadge = document.getElementById("ml-duration-badge");

  // Lists
  const checksContainer = document.getElementById("checks-container");
  const findingsContainer = document.getElementById("findings-container");
  const recommendationsContainer = document.getElementById("recommendations-container");
  const btnScanAnother = document.getElementById("btn-scan-another");

  let isScanning = false;
  let scanProgressTimer = null;

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

  // Form submit handler with progressive cold-start detection
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearError();

    if (isScanning) return;

    const validation = validateUrlInput(urlInput.value);
    if (!validation.valid) {
      showError(validation.message);
      urlInput.focus();
      return;
    }

    isScanning = true;
    showView("scanning");
    btnScan.disabled = true;
    btnScanText.textContent = "Scanning Website...";

    if (scanningStatusText) {
      scanningStatusText.textContent = "Connecting to destination, inspecting TLS certificates, and analyzing redirect path...";
    }

    const startTime = Date.now();
    scanProgressTimer = setInterval(() => {
      const elapsedSec = Math.floor((Date.now() - startTime) / 1000);
      if (elapsedSec >= 15 && scanningStatusText) {
        scanningStatusText.textContent = "🔄 Still initializing... The cloud backend is completing its startup cycle. Processing your scan shortly.";
      } else if (elapsedSec >= 4 && scanningStatusText) {
        scanningStatusText.textContent = "⏳ Contacting backend server... If the Render cloud backend is waking up (cold start), this may take 15–25 seconds. Please wait.";
      }
    }, 1000);

    try {
      const endpoint = (cfg && cfg.ENDPOINTS && cfg.ENDPOINTS.urlScan) ? cfg.ENDPOINTS.urlScan : "/api/url-scan";
      const payload = { 
        url: validation.url,
        fast_scan_only: fastScanToggle ? fastScanToggle.checked : false
      };

      const result = await apiFetch(endpoint, {
        method: "POST",
        body: payload
      });

      clearInterval(scanProgressTimer);
      renderScanResults(result);
      showView("result");
    } catch (err) {
      clearInterval(scanProgressTimer);
      console.error("[URL Scanner Error]", err);

      if (err.status === 400 && (err.detail || "").includes("SSRF")) {
        resErrorTitle.textContent = "Security Policy Violation (SSRF)";
        resErrorMessage.textContent = err.detail || "Access to internal, loopback, or cloud metadata addresses is strictly prohibited by SSRF security policy.";
      } else if (err.status === 422) {
        resErrorTitle.textContent = "Invalid URL Format";
        resErrorMessage.textContent = err.detail || "The submitted URL could not be processed. Please check the address format.";
      } else if (err.status === 405) {
        resErrorTitle.textContent = "Backend Update Required";
        resErrorMessage.textContent = "The backend service has not finished deploying the latest URL Scanner update. Please trigger 'Manual Deploy' -> 'Deploy latest commit' in your Render dashboard.";
      } else if (err.status === 408 || (err.message && err.message.includes("Render"))) {
        resErrorTitle.textContent = "Backend Connection Timeout";
        resErrorMessage.textContent = "The server took too long to respond. The Render free-tier cloud backend may be waking up from sleep. Please click 'Try Again' now that the backend is awake.";
      } else if (!err.status || err.status === 0) {
        // Probe health endpoint to distinguish cold-start / redeployment from network outage
        let isBackendOnline = false;
        try {
          const healthRes = await fetch(window.ScamShield.buildApiUrl("/health"), { method: "GET", signal: AbortSignal.timeout(3000) });
          isBackendOnline = healthRes.ok;
        } catch (_) {}

        if (isBackendOnline) {
          resErrorTitle.textContent = "Backend Endpoint Redeployment Pending";
          resErrorMessage.textContent = "The cloud backend is online, but the URL Scanner endpoint is not active yet on Render. Please trigger 'Manual Deploy' -> 'Deploy latest commit' in your Render dashboard.";
        } else {
          resErrorTitle.textContent = "Backend Cold Start / Connection Error";
          resErrorMessage.textContent = "Could not establish connection to the cloud backend. If hosted on Render free tier, the instance may be waking up from sleep (takes 30-50s). Please try again shortly.";
        }
      } else {
        resErrorTitle.textContent = "Inspection Request Failed";
        resErrorMessage.textContent = err.detail || err.message || "Failed to inspect website. Please verify your connection and try again.";
      }
      showView("error");
    } finally {
      clearInterval(scanProgressTimer);
      isScanning = false;
      btnScan.disabled = false;
      btnScanText.textContent = "🛡️ Scan Website with Security Engine";
    }
  });

  // Render scan results
  function renderScanResults(data) {
    const classification = data.classification || "Unknown";
    const score = typeof data.risk_score === "number" ? data.risk_score : 0;
    const normalizedUrl = data.normalized_url || data.url;

    // Timestamp & Execution Duration
    const dateFormatted = data.scan_timestamp ? formatDateTime(data.scan_timestamp) : "Just now";
    if (typeof data.scan_duration_ms === "number") {
      timestampBadge.textContent = `Scanned in ${data.scan_duration_ms.toFixed(0)}ms • ${dateFormatted}`;
    } else {
      timestampBadge.textContent = `Scanned: ${dateFormatted}`;
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
    } else if (classification === "Unknown") {
      resVerdictBox.classList.add("warning");
      resVerdictIcon.textContent = "❓";
      resVerdictTitle.textContent = "Unknown / Inconclusive Risk";
      resVerdictTitle.style.color = "#94A3B8";
      resThreatBar.style.background = "#64748B";
      resScoreDesc.textContent = "Destination could not be definitively verified due to server reachability or domain configuration. Insufficient evidence to determine safety.";
    } else {
      resVerdictBox.classList.add("safe");
      resVerdictIcon.textContent = "✅";
      resVerdictTitle.textContent = "Low Technical Risk Website";
      resVerdictTitle.style.color = "#34D399";
      resThreatBar.classList.add("safe");
      resThreatBar.style.background = "#10B981";
      resScoreDesc.textContent = "No prominent phishing or technical evasion indicators detected. Always confirm legitimacy before disclosing credentials.";
    }

    resVerdictSubtitle.textContent = normalizedUrl;
    resThreatScore.textContent = `${score.toFixed(1)} / 100`;
    resThreatBar.style.width = `${Math.min(Math.max(score, 5), 100)}%`;

    // Render ML Model Phishing Verdict Banner
    if (mlVerdictBanner && data.ml_prediction && data.ml_prediction.available) {
      const ml = data.ml_prediction;
      mlVerdictBanner.style.display = "flex";
      const probPct = (ml.phishing_probability * 100).toFixed(1);
      const isPhish = ml.is_phishing;
      mlVerdictText.textContent = `${ml.model_name || 'Machine Learning'}: ${ml.predicted_class || (isPhish ? 'Phishing' : 'Benign')} (${ml.confidence_percentage || probPct + '%'} confidence)`;
      
      if (isPhish) {
        mlProbBadge.textContent = `Risk: ${probPct}% (Phishing)`;
        mlProbBadge.style.background = "rgba(239, 68, 68, 0.15)";
        mlProbBadge.style.color = "#F87171";
        mlProbBadge.style.borderColor = "rgba(239, 68, 68, 0.35)";
      } else {
        mlProbBadge.textContent = `Risk: ${probPct}% (Benign)`;
        mlProbBadge.style.background = "rgba(16, 185, 129, 0.15)";
        mlProbBadge.style.color = "#34D399";
        mlProbBadge.style.borderColor = "rgba(16, 185, 129, 0.35)";
      }
      if (typeof ml.duration_ms === "number") {
        mlDurationBadge.textContent = `⚡${ml.duration_ms.toFixed(1)}ms`;
      }
    } else if (mlVerdictBanner) {
      mlVerdictBanner.style.display = "none";
    }

    // Metrics Tiles
    const domainInfo = data.domain_info || {};
    const httpsInfo = data.https_info || {};
    const redirectInfo = data.redirect_info || {};

    tileDomain.textContent = domainInfo.registered_domain || domainInfo.host || "--";
    tileIp.textContent = data.resolved_ip || "--";

    if (httpsInfo.is_https) {
      if (httpsInfo.cert_valid) {
        tileTls.innerHTML = `<span style="color:#34D399;">🔒 HTTPS (Valid)</span><div style="font-size:0.75rem; color:var(--text-dim); margin-top:2px;">${httpsInfo.issuer || ""}</div>`;
      } else if (httpsInfo.cert_valid === false) {
        tileTls.innerHTML = `<span style="color:#F87171;">⚠️ HTTPS (Invalid Cert)</span>`;
      } else {
        tileTls.innerHTML = `<span style="color:#94A3B8;">⚪ TLS (Unverified)</span>`;
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

    // Security Checks List with Per-Check Execution Timings
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

        let timeHtml = "";
        if (typeof chk.duration_ms === "number") {
          timeHtml = `<span style="font-size:0.72rem; font-family:var(--font-mono); color:var(--text-dim); margin-left:6px; opacity:0.8;">⚡${chk.duration_ms.toFixed(0)}ms</span>`;
        }

        titleDiv.innerHTML = `<span>${icon}</span> <span>${chk.name}</span> <span class="check-cat">${chk.category}</span> ${timeHtml}`;

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
      engineBadge.textContent = "🛡️ Real-Time Cyber Engine";
      engineBadge.style.background = "rgba(6, 182, 212, 0.15)";
      engineBadge.style.color = "#67E8F9";
      engineBadge.style.borderColor = "rgba(6, 182, 212, 0.3)";
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
