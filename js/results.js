/* ==========================================================================
   ScamShield AI — Detailed Results Controller
   ========================================================================== */

(function () {
  "use strict";

  const { apiFetch, toast, cfg } = window.ScamShield;

  const noResultBox = document.getElementById("no-result-state");
  const detailBox = document.getElementById("result-detail-container");

  const resBanner = document.getElementById("res-banner");
  const resIcon = document.getElementById("res-icon");
  const resTitle = document.getElementById("res-title");
  const resSubtitle = document.getElementById("res-subtitle");
  const resBadge = document.getElementById("res-badge");
  const resScorePct = document.getElementById("res-score-pct");
  const resMeterFill = document.getElementById("res-meter-fill");
  const resMargin = document.getElementById("res-margin");
  const resLabel = document.getElementById("res-label");
  const resText = document.getElementById("res-text");
  const resIndicators = document.getElementById("res-indicators");
  const resRecs = document.getElementById("res-recommendations");
  const btnDownloadPdf = document.getElementById("btn-download-pdf");

  let currentResult = null;

  async function loadResult() {
    // 1. Try reading from sessionStorage
    const stored = sessionStorage.getItem("scamshield_latest_result");
    if (stored) {
      try {
        currentResult = JSON.parse(stored);
        displayResult(currentResult);
        return;
      } catch (_) {}
    }

    // 2. Try reading from URL query parameter ?id=...
    const params = new URLSearchParams(window.location.search);
    const scanId = params.get("id");
    if (scanId) {
      try {
        const history = await apiFetch(cfg.ENDPOINTS.history);
        const match = (history || []).find(item => String(item.id) === String(scanId));
        if (match) {
          currentResult = match;
          displayResult(match);
          return;
        }
      } catch (_) {}
    }

    // If nothing found, show empty state
    noResultBox.style.display = "block";
    detailBox.style.display = "none";
  }

  function displayResult(data) {
    noResultBox.style.display = "none";
    detailBox.style.display = "block";

    const isScam = data.is_scam;
    resBanner.className = `verdict-box ${isScam ? "scam" : "safe"}`;
    resIcon.textContent = isScam ? "🚨" : "✅";
    resTitle.textContent = isScam ? "Scam / Suspicious Detected" : "Legitimate Message Verified";
    resSubtitle.textContent = isScam
      ? "High probability of fraud, phishing lure, or credential theft."
      : "Message structure and terms match legitimate communication patterns.";

    resBadge.className = `status-pill ${isScam ? "scam" : "safe"}`;
    resBadge.textContent = data.risk_level ? data.risk_level.replace("_", " ") : (isScam ? "HIGH RISK" : "CLEAN");

    const pct = Math.round(data.confidence * 100);
    resScorePct.textContent = `${pct}%`;
    resMeterFill.style.width = `${pct}%`;
    resMeterFill.style.background = isScam
      ? "linear-gradient(90deg, #F59E0B, #EF4444)"
      : "linear-gradient(90deg, #3B82F6, #10B981)";

    resMargin.textContent = data.decision_margin !== null
      ? (data.decision_margin > 0 ? "+" : "") + data.decision_margin
      : "N/A";
    resLabel.textContent = data.predicted_label;
    resText.textContent = data.message_text || data.text_preview || "No message content recorded.";

    // Indicators
    resIndicators.innerHTML = "";
    const indicators = data.indicators_detected || [];
    if (indicators.length > 0) {
      indicators.forEach(tag => {
        const span = document.createElement("span");
        span.className = "tag-badge";
        span.textContent = `⚠️ ${tag}`;
        resIndicators.appendChild(span);
      });
    } else {
      const span = document.createElement("span");
      span.className = "tag-badge";
      span.style.background = "rgba(255,255,255,0.05)";
      span.style.borderColor = "var(--navy-border)";
      span.style.color = "var(--text-dim)";
      span.textContent = "No specific heuristic triggers detected";
      resIndicators.appendChild(span);
    }

    // Safety Recommendations
    if (isScam) {
      resRecs.innerHTML = `
        <p><strong>1. Do NOT click any links:</strong> URLs in suspicious messages often lead to credential harvesting portals or drive-by malware.</p>
        <p><strong>2. Never provide OTPs or passwords:</strong> Legitimate banks and service providers will never ask for your verification code or password over SMS/email.</p>
        <p><strong>3. Verify through official channels:</strong> If this claims to be from your bank or an employer, call their verified public phone number directly.</p>
        <p><strong>4. Report the sender:</strong> Mark the message as spam in your email/SMS client to alert telecom operators.</p>
      `;
    } else {
      resRecs.innerHTML = `
        <p><strong>1. Standard security hygiene:</strong> Even though this message was not classified as a scam, remain cautious with unexpected file attachments.</p>
        <p><strong>2. Confirm sender domain:</strong> Verify that the sender email domain exactly matches the expected company or contact.</p>
        <p><strong>3. Zero-trust principles:</strong> If the message requests wire transfers or account changes, always confirm via secondary verification.</p>
      `;
    }
  }

  // PDF Report Download
  btnDownloadPdf.addEventListener("click", async () => {
    if (!currentResult) return;

    btnDownloadPdf.disabled = true;
    btnDownloadPdf.classList.add("loading");

    try {
      let blob;
      if (currentResult.id || currentResult.scan_id) {
        const id = currentResult.id || currentResult.scan_id;
        blob = await apiFetch(cfg.ENDPOINTS.downloadReportById(id));
      } else {
        blob = await apiFetch(cfg.ENDPOINTS.downloadCustomReport, {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify(currentResult)
        });
      }

      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = downloadUrl;
      a.download = `ScamShield_Audit_Report.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(downloadUrl);
      toast("PDF report downloaded successfully!", "success");
    } catch (err) {
      toast(`Failed to download report: ${err.message}`, "error");
    } finally {
      btnDownloadPdf.disabled = false;
      btnDownloadPdf.classList.remove("loading");
    }
  });

  loadResult();
})();
