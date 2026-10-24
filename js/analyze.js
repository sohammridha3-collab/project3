/* ==========================================================================
   ScamShield AI — Message Analysis Controller
   ========================================================================== */

(function () {
  "use strict";

  const { apiFetch, ApiError, toast, cfg } = window.ScamShield;

  let currentType = "sms";
  let latestResult = null;

  // Preset Sample Messages
  const PRESETS = {
    bank: {
      type: "email",
      subject: "SECURITY ALERT: Immediate Action Required on Your Bank Account",
      body: "Dear Customer, We have detected unauthorized login attempts from an unrecognized device. Your account access has been temporarily suspended. Please click http://secure-bank-verify.fake-portal.com to confirm your password and identity within 24 hours to prevent account closure."
    },
    lottery: {
      type: "sms",
      body: "WINNER! You have won a $1,000,000 Walmart cash gift card. Call 1-800-555-0199 now or click http://claim-prize-now.com to claim before expiration."
    },
    work: {
      type: "email",
      subject: "Quarterly Strategy Review & Deck Slides",
      body: "Hi team, please find attached the agenda and presentation deck for tomorrow morning's strategic sync at 10 AM in Conference Room B. Let me know if you have any feedback or slides to add."
    },
    sms: {
      type: "sms",
      body: "Hey, are we still meeting at the library at 5 PM? Let me know when you get there!"
    }
  };

  // DOM Elements
  const typeSmsBtn = document.getElementById("type-sms");
  const typeEmailBtn = document.getElementById("type-email");
  const subjectGroup = document.getElementById("subject-group");
  const subjectInput = document.getElementById("msg-subject");
  const bodyInput = document.getElementById("msg-body");
  const charCounter = document.getElementById("char-counter");
  const analyzeForm = document.getElementById("analyze-form");
  const analyzeBtn = document.getElementById("btn-analyze");
  const analyzeBtnText = document.getElementById("btn-analyze-text");
  const errorBox = document.getElementById("analyze-error");

  const placeholder = document.getElementById("result-placeholder");
  const scanningCard = document.getElementById("result-scanning");
  const resultError = document.getElementById("result-error");
  const resErrorTitle = document.getElementById("res-error-title");
  const resErrorMessage = document.getElementById("res-error-message");
  const btnRetryAnalyze = document.getElementById("btn-retry-analyze");
  const resultCard = document.getElementById("result-card");
  const resBanner = document.getElementById("res-banner");
  const resIcon = document.getElementById("res-icon");
  const resTitle = document.getElementById("res-title");
  const resSubtitle = document.getElementById("res-subtitle");
  const resScorePct = document.getElementById("res-score-pct");
  const resMeterFill = document.getElementById("res-meter-fill");
  const resMargin = document.getElementById("res-margin");
  const resRisk = document.getElementById("res-risk");
  const resLabel = document.getElementById("res-label");
  const resChars = document.getElementById("res-chars");
  const resIndicators = document.getElementById("res-indicators");
  const resLatency = document.getElementById("res-latency");
  const safetyItems = document.getElementById("safety-items");

  const btnDownloadPdf = document.getElementById("btn-download-pdf");
  const btnScanAgain = document.getElementById("btn-scan-again");

  // Type Toggle Handler
  function setMessageType(type) {
    currentType = type;
    if (type === "email") {
      typeEmailBtn.classList.add("active");
      typeSmsBtn.classList.remove("active");
      subjectGroup.style.display = "block";
    } else {
      typeSmsBtn.classList.add("active");
      typeEmailBtn.classList.remove("active");
      subjectGroup.style.display = "none";
    }
  }

  typeSmsBtn.addEventListener("click", () => setMessageType("sms"));
  typeEmailBtn.addEventListener("click", () => setMessageType("email"));

  // Preset Chips
  document.querySelectorAll(".preset-chips .chip").forEach(chip => {
    chip.addEventListener("click", () => {
      const key = chip.getAttribute("data-sample");
      const sample = PRESETS[key];
      if (!sample) return;

      setMessageType(sample.type || "sms");
      if (sample.subject) subjectInput.value = sample.subject;
      else subjectInput.value = "";
      bodyInput.value = sample.body || "";
      updateCharCounter();
      toast(`Loaded preset: ${chip.textContent.trim()}`);
    });
  });

  // Character Counter
  function updateCharCounter() {
    const len = bodyInput.value.length;
    charCounter.textContent = `${len} / ${cfg.MAX_CHARS}`;
    if (len > cfg.MAX_CHARS) {
      charCounter.style.color = "var(--scam)";
    } else {
      charCounter.style.color = "var(--text-dim)";
    }
  }

  bodyInput.addEventListener("input", () => {
    updateCharCounter();
    errorBox.hidden = true;
  });

  bodyInput.addEventListener("keydown", e => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      analyzeForm.dispatchEvent(new Event("submit"));
    }
  });

  // Tools: Paste & Clear
  document.getElementById("btn-paste").addEventListener("click", async () => {
    try {
      const text = await navigator.clipboard.readText();
      bodyInput.value = text;
      updateCharCounter();
      toast("Pasted from clipboard", "info");
    } catch (_) {
      toast("Clipboard access blocked. Please use Ctrl+V / Cmd+V.", "error");
    }
  });

  function resetWorkspace() {
    bodyInput.value = "";
    subjectInput.value = "";
    updateCharCounter();
    errorBox.hidden = true;
    if (resultError) resultError.style.display = "none";
    if (resultCard) resultCard.style.display = "none";
    if (scanningCard) scanningCard.style.display = "none";
    if (placeholder) placeholder.style.display = "block";
    latestResult = null;
    bodyInput.focus();
  }

  document.getElementById("btn-clear").addEventListener("click", resetWorkspace);
  if (btnScanAgain) {
    btnScanAgain.addEventListener("click", resetWorkspace);
  }

  if (btnRetryAnalyze) {
    btnRetryAnalyze.addEventListener("click", () => {
      if (resultError) resultError.style.display = "none";
      if (bodyInput.value.trim() || subjectInput.value.trim()) {
        analyzeForm.dispatchEvent(new Event("submit"));
      } else {
        if (placeholder) placeholder.style.display = "block";
        bodyInput.focus();
      }
    });
  }

  // Form Submission & Threat Prediction
  analyzeForm.addEventListener("submit", async e => {
    e.preventDefault();
    errorBox.hidden = true;

    const bodyText = bodyInput.value.trim();
    const subjectText = subjectInput.value.trim();

    if (!bodyText && !subjectText) {
      errorBox.textContent = "Please enter message text or subject to screen.";
      errorBox.hidden = false;
      return;
    }

    if (bodyText.length > cfg.MAX_CHARS) {
      errorBox.textContent = `Message length (${bodyText.length}) exceeds safety limit of ${cfg.MAX_CHARS} characters.`;
      errorBox.hidden = false;
      return;
    }

    // Activate scanning state
    analyzeBtn.disabled = true;
    analyzeBtn.classList.add("loading");
    analyzeBtnText.textContent = "Screening with ML Pipeline...";
    if (placeholder) placeholder.style.display = "none";
    if (resultError) resultError.style.display = "none";
    if (resultCard) resultCard.style.display = "none";
    if (scanningCard) scanningCard.style.display = "block";
    const startTime = performance.now();

    try {
      const payload = {
        message_type: currentType,
        text: bodyText
      };

      if (currentType === "email" && subjectText) {
        payload.subject = subjectText;
        payload.body = bodyText;
      }

      const res = await apiFetch(cfg.ENDPOINTS.predict, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      });

      const elapsed = Math.round(performance.now() - startTime);
      latestResult = res;
      sessionStorage.setItem("scamshield_latest_result", JSON.stringify(res));

      renderResult(res, elapsed);
      toast(res.is_scam ? "🚨 Threat Detected!" : "✅ Message Classified as Clean", res.is_scam ? "error" : "success");
    } catch (err) {
      console.error("[ScamShield Analyze Error]", err);
      if (scanningCard) scanningCard.style.display = "none";
      if (placeholder) placeholder.style.display = "none";
      if (resultCard) resultCard.style.display = "none";
      if (resultError) {
        resultError.style.display = "block";
        if (resErrorMessage) {
          resErrorMessage.textContent = err.detail || err.message || "Failed to complete message screening.";
        }
      }
      errorBox.textContent = err.detail || err.message || "Failed to complete message screening.";
      errorBox.hidden = false;
    } finally {
      analyzeBtn.disabled = false;
      analyzeBtn.classList.remove("loading");
      analyzeBtnText.textContent = "Scan Message with AI Pipeline";
    }
  });

  // Render Result in Right Column
  function renderResult(data, elapsedMs) {
    if (placeholder) placeholder.style.display = "none";
    if (scanningCard) scanningCard.style.display = "none";
    if (resultError) resultError.style.display = "none";
    if (resultCard) resultCard.style.display = "block";

    resLatency.textContent = `${elapsedMs} ms latency`;

    // Verdict Banner
    if (data.is_borderline || data.risk_level === "BORDERLINE_UNCERTAIN") {
      resBanner.className = "verdict-box";
      resBanner.style.borderColor = "rgba(245, 158, 11, 0.5)";
      resBanner.style.background = "rgba(245, 158, 11, 0.08)";
      resIcon.textContent = "⚠️";
      resTitle.textContent = "Borderline / Uncertain Signal";
      resSubtitle.textContent = "Message is close to the linear decision boundary with no overt fraud keywords detected. Caution advised.";
    } else if (data.is_scam) {
      resBanner.className = "verdict-box scam";
      resBanner.style.borderColor = "";
      resBanner.style.background = "";
      resIcon.textContent = "🚨";
      resTitle.textContent = "Scam / Phishing Detected";
      resSubtitle.textContent = "High probability of malicious intent, credential theft, or fraud.";
    } else {
      resBanner.className = "verdict-box safe";
      resBanner.style.borderColor = "";
      resBanner.style.background = "";
      resIcon.textContent = "✅";
      resTitle.textContent = "Legitimate Message";
      resSubtitle.textContent = "Message pattern is consistent with standard, non-malicious communication.";
    }

    // Score meter
    const threatVal = (data.threat_score !== undefined && data.threat_score !== null)
      ? data.threat_score
      : (data.is_scam ? data.confidence : (1.0 - data.confidence));
    const pct = Math.round(threatVal * 100);
    resScorePct.textContent = data.threat_score_percentage || `${pct}%`;
    resMeterFill.style.width = `${pct}%`;
    resMeterFill.style.background = data.is_scam
      ? "linear-gradient(90deg, #F59E0B, #EF4444)"
      : "linear-gradient(90deg, #3B82F6, #10B981)";

    // Technical tiles
    resMargin.textContent = (data.decision_margin !== null && data.decision_margin !== undefined)
      ? (data.decision_margin > 0 ? "+" : "") + Number(data.decision_margin).toFixed(3)
      : "N/A";
    resRisk.textContent = data.risk_level ? data.risk_level.replaceAll("_", " ") : (data.is_scam ? "HIGH RISK" : "LOW RISK");
    resRisk.style.color = data.is_scam ? "#F87171" : "#34D399";
    resLabel.textContent = data.predicted_label !== undefined ? data.predicted_label : (data.is_scam ? 1 : 0);
    resChars.textContent = data.character_count || bodyInput.value.length;

    // Indicators (Safe DOM insertion)
    resIndicators.innerHTML = "";
    if (data.indicators_detected && data.indicators_detected.length > 0) {
      data.indicators_detected.forEach(tag => {
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

    // Safety Recommendations Guidance (Safe DOM insertion)
    if (safetyItems) {
      safetyItems.innerHTML = "";
      const tips = data.is_scam ? [
        "🚫 Do not click any embedded links, buttons, or downloadable attachments.",
        "🔒 Never disclose your one-time passwords (OTP), banking PINs, or account credentials.",
        "📞 Verify the purported sender independently using verified official telephone numbers.",
        "🛑 Report this message directly to your organization's IT security or national cyber-crime portal."
      ] : [
        "✅ Message characteristics align with typical legitimate, non-malicious text communications.",
        "⚠️ Exercise general cybersecurity hygiene: always verify senders if unexpected requests occur.",
        "🔍 Note: Statistical classification cannot guarantee 100% absence of zero-day social engineering."
      ];

      tips.forEach(tip => {
        const item = document.createElement("div");
        item.className = "safety-item";
        item.textContent = tip;
        safetyItems.appendChild(item);
      });
    }
  }

  // Action: Download PDF Report
  btnDownloadPdf.addEventListener("click", async () => {
    if (!latestResult) return;

    btnDownloadPdf.disabled = true;
    btnDownloadPdf.classList.add("loading");

    try {
      let blob;
      if (latestResult.scan_id) {
        blob = await apiFetch(cfg.ENDPOINTS.downloadReportById(latestResult.scan_id));
      } else {
        blob = await apiFetch(cfg.ENDPOINTS.downloadCustomReport, {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify(latestResult)
        });
      }

      // Trigger browser download
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = downloadUrl;
      a.download = `ScamShield_Audit_${latestResult.scan_id || "Report"}.pdf`;
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

  // Action: Reset / Scan Again
  if (btnScanAgain) {
    btnScanAgain.addEventListener("click", resetWorkspace);
  }
})();
