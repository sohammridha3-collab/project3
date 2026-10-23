/* ==========================================================================
   ScamShield AI — Scan & Audio Call History Controller
   ========================================================================== */

(function () {
  "use strict";

  const { apiFetch, requireAuth, toast, cfg, formatDateTime, formatRelativeTime } = window.ScamShield;

  // Protect page: require login
  requireAuth();

  let activeRecordType = "all";  // "all" | "message" | "call"
  let activeFilter = "all";      // "all" | "scam" | "legitimate"
  let searchDebounceTimer = null;
  let activeRecordInModal = null;

  // DOM Elements
  const recordTypeBtns = document.querySelectorAll("#record-type-tabs .type-btn");
  const filterBtns = document.querySelectorAll("#filter-pills .type-btn");
  const searchInput = document.getElementById("history-search");
  const emptyBox = document.getElementById("history-empty");
  const emptyTitle = document.getElementById("empty-title");
  const emptyDesc = document.getElementById("empty-desc");
  const tableWrap = document.getElementById("history-table-wrap");
  const tbody = document.getElementById("history-tbody");
  const btnClearAll = document.getElementById("btn-clear-all");

  // Modal Elements
  const modalBackdrop = document.getElementById("modal-record-detail");
  const modalIcon = document.getElementById("modal-icon");
  const modalTitle = document.getElementById("modal-title");
  const modalSubtitle = document.getElementById("modal-subtitle");
  const modalBody = document.getElementById("modal-body-content");
  const btnCloseModal = document.getElementById("btn-close-modal");
  const btnDismissModal = document.getElementById("btn-dismiss-modal");
  const modalBtnDownloadPdf = document.getElementById("modal-btn-download-pdf");

  // Record Type Tabs
  recordTypeBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      recordTypeBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      activeRecordType = btn.getAttribute("data-record-type") || "all";
      loadHistory();
    });
  });

  // Threat Verdict Filters
  filterBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      filterBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      activeFilter = btn.getAttribute("data-filter") || "all";
      loadHistory();
    });
  });

  // Search Input with Debouncing
  searchInput.addEventListener("input", () => {
    clearTimeout(searchDebounceTimer);
    searchDebounceTimer = setTimeout(() => {
      loadHistory();
    }, 300);
  });

  // Load and Render Unified History
  async function loadHistory() {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:2.5rem; color:var(--text-dim);">Loading analysis records...</td></tr>`;

    try {
      const searchTerm = searchInput.value.trim();
      let queryUrl = `${cfg.ENDPOINTS.history}?filter_type=${activeFilter}&record_type=${activeRecordType}`;
      if (searchTerm) {
        queryUrl += `&search=${encodeURIComponent(searchTerm)}`;
      }

      const records = await apiFetch(queryUrl);

      if (!records || records.length === 0) {
        emptyBox.style.display = "block";
        tableWrap.style.display = "none";
        if (searchTerm) {
          emptyTitle.textContent = "No Records Match Your Search";
          emptyDesc.textContent = `No stored analyses matched "${searchTerm}". Try broadening your search query or switching filters.`;
        } else if (activeRecordType === "call") {
          emptyTitle.textContent = "No CallScam Audio Analyses Recorded";
          emptyDesc.textContent = "You have not evaluated any audio call recordings yet. Upload or record a call to screen for voice phishing.";
        } else if (activeRecordType === "message") {
          emptyTitle.textContent = "No Message Analyses Recorded";
          emptyDesc.textContent = "No message screenings found for this filter criteria.";
        } else {
          emptyTitle.textContent = "Your Analysis Archive is Empty";
          emptyDesc.textContent = "Scan a message or upload a call recording while signed in to securely preserve your cybersecurity audit records.";
        }
        return;
      }

      emptyBox.style.display = "none";
      tableWrap.style.display = "block";
      tbody.innerHTML = "";

      records.forEach(r => {
        const tr = document.createElement("tr");

        // Format Date consistently using user local timezone (e.g. 23 Oct 2026, 3:27 PM)
        const dateStr = formatDateTime(r.created_at);
        const relTime = formatRelativeTime(r.created_at);

        const isCall = r.record_type === "call" || r.message_type === "call";
        const isScam = r.is_scam;

        // Content preview
        const rawContent = r.transcript || r.message_text || "";
        const preview = rawContent.length > 70
          ? rawContent.substring(0, 67) + "..."
          : rawContent;

        const secondaryInfo = isCall
          ? (r.audio_filename ? `🎧 ${r.audio_filename}` : "🎙️ Voice Recording")
          : (r.subject ? `Subj: ${r.subject.substring(0, 32)}` : "");

        const languageLabel = isCall
          ? (r.language_name || (r.detected_language ? r.detected_language.toUpperCase() : "English"))
          : "—";

        tr.innerHTML = `
          <td style="font-family:var(--font-mono); font-weight:700; color:var(--cyan); white-space:nowrap;">
            #${r.id}
          </td>
          <td style="white-space:nowrap; font-size:0.85rem;">
            <div style="font-weight:600; color:var(--text);">${dateStr}</div>
            ${relTime ? `<div style="font-size:0.75rem; color:var(--text-dim); margin-top:2px;">${relTime}</div>` : ""}
          </td>
          <td>
            <span style="font-size:0.75rem; padding:2px 8px; border-radius:6px; font-weight:600; display:inline-flex; align-items:center; gap:4px; ${isCall ? "background:rgba(139,92,246,0.15); color:#C4B5FD; border:1px solid rgba(139,92,246,0.3);" : "background:rgba(59,130,246,0.15); color:#93C5FD; border:1px solid rgba(59,130,246,0.3);"}">
              ${isCall ? "🎙️ Call" : (r.message_type === "email" ? "✉️ Email" : "📱 SMS")}
            </span>
          </td>
          <td style="max-width:280px; font-weight:500;">
            <div class="hist-preview-text" style="text-overflow:ellipsis; overflow:hidden; white-space:nowrap;"></div>
            ${secondaryInfo ? `<div style="font-size:0.75rem; color:var(--text-dim); margin-top:2px;">${secondaryInfo}</div>` : ""}
          </td>
          <td>
            <span style="font-size:0.8rem; color:var(--text-muted); font-weight:500;">${languageLabel}</span>
          </td>
          <td>
            <span class="status-pill ${isScam ? "scam" : "safe"}">
              ${isScam ? "🚨 Threat" : "✅ Clean"}
            </span>
          </td>
          <td style="font-family:var(--font-mono); font-weight:600; font-size:0.88rem;">
            ${r.confidence_percentage}
          </td>
          <td style="white-space:nowrap;">
            <div style="display:flex; gap:0.4rem;">
              <button type="button" class="btn btn-ghost btn-sm btn-view-record" title="View Full Analysis Details">🔍</button>
              <button type="button" class="btn btn-ghost btn-sm btn-dl-pdf" title="Download Official PDF Report">📄</button>
              <button type="button" class="btn btn-danger btn-sm btn-del-record" title="Delete Record">🗑️</button>
            </div>
          </td>
        `;

        // Safe preview assignment
        tr.querySelector(".hist-preview-text").textContent = preview;

        // View Details Button
        tr.querySelector(".btn-view-record").addEventListener("click", () => {
          openRecordModal(r);
        });

        // Download PDF Report
        const dlBtn = tr.querySelector(".btn-dl-pdf");
        dlBtn.addEventListener("click", async () => {
          dlBtn.disabled = true;
          try {
            const endpoint = isCall
              ? cfg.ENDPOINTS.downloadCallReportById(r.id)
              : cfg.ENDPOINTS.downloadReportById(r.id);

            const blob = await apiFetch(endpoint);
            const downloadUrl = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = downloadUrl;
            a.download = `ScamShield_${isCall ? "CallAudit" : "Report"}_${r.id}.pdf`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(downloadUrl);
            toast(`Downloaded PDF report for #${r.id}`, "success");
          } catch (err) {
            toast(`Download failed: ${err.message}`, "error");
          } finally {
            dlBtn.disabled = false;
          }
        });

        // Delete Record
        tr.querySelector(".btn-del-record").addEventListener("click", async () => {
          const typeName = isCall ? "CallScam audio record" : "message scan";
          if (!confirm(`Are you sure you want to permanently delete ${typeName} #${r.id}?`)) return;

          try {
            const delEndpoint = `${cfg.ENDPOINTS.deleteScan(r.id)}?record_type=${isCall ? "call" : "message"}`;
            await apiFetch(delEndpoint, { method: "DELETE" });
            toast(`Record #${r.id} deleted successfully.`, "info");
            loadHistory();
          } catch (err) {
            toast(`Delete failed: ${err.message}`, "error");
          }
        });

        tbody.appendChild(tr);
      });
    } catch (err) {
      toast(`Failed to load history: ${err.message}`, "error");
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:2rem; color:#F87171;">Error loading history: ${err.message}</td></tr>`;
    }
  }

  // Open Details Modal
  function openRecordModal(r) {
    activeRecordInModal = r;
    const isCall = r.record_type === "call" || r.message_type === "call";
    const dateStr = formatDateTime(r.created_at);

    modalIcon.textContent = isCall ? "🎙️" : "📩";
    modalTitle.textContent = isCall ? "CallScam Voice Threat Assessment" : "Message Threat Screening";
    modalSubtitle.textContent = `Audit Record #${r.id} • ${dateStr}`;

    const indicators = r.indicators_detected || [];
    const textContent = r.transcript || r.message_text || "No content preserved.";

    modalBody.innerHTML = `
      <!-- Verdict Banner -->
      <div class="verdict-box ${r.is_scam ? "scam" : "safe"}" style="margin-bottom:1.25rem;">
        <div class="verdict-icon">${r.is_scam ? "🚨" : "✅"}</div>
        <div>
          <div class="verdict-title">${r.is_scam ? "Flagged Threat / Scam" : "Legitimate / Non-Malicious"}</div>
          <div class="verdict-sub">Classified as ${r.predicted_class || (r.is_scam ? "Scam" : "Legitimate")} • Confidence: ${r.confidence_percentage}</div>
        </div>
      </div>

      <!-- Metadata Grid -->
      <div class="metrics-2col" style="margin-bottom:1.25rem;">
        <div class="metric-tile">
          <div class="k">Record Category</div>
          <div class="v" style="font-size:1rem;">${isCall ? "🎙️ Audio Recording" : `📩 Message (${r.message_type || "auto"})`}</div>
        </div>
        <div class="metric-tile">
          <div class="k">${isCall ? "Detected Spoken Language" : "Decision Boundary Margin"}</div>
          <div class="v" style="font-size:1rem;">${isCall ? (r.language_name || r.detected_language || "English") : (r.decision_margin !== null && r.decision_margin !== undefined ? Number(r.decision_margin).toFixed(3) : "N/A")}</div>
        </div>
        <div class="metric-tile">
          <div class="k">Risk Rating</div>
          <div class="v" style="font-size:1rem; color:${r.is_scam ? "#F87171" : "#34D399"};">${r.risk_level ? r.risk_level.replaceAll("_", " ") : (r.is_scam ? "HIGH RISK" : "SAFE")}</div>
        </div>
        <div class="metric-tile">
          <div class="k">${isCall ? "Call Duration" : "Subject"}</div>
          <div class="v" style="font-size:1rem;">${isCall ? (r.duration_seconds ? `${r.duration_seconds.toFixed(1)}s` : "Recorded Audio") : (r.subject ? r.subject.substring(0, 25) : "—")}</div>
        </div>
      </div>

      <!-- Preserved Content / Transcript -->
      <div style="margin-bottom:1.25rem;">
        <div style="font-size:0.78rem; font-weight:700; text-transform:uppercase; color:var(--text-dim); margin-bottom:0.5rem;">
          ${isCall ? "🎧 Transcribed Speech" : "📄 Screened Message Text"}
        </div>
        <div style="background:rgba(0,0,0,0.3); border:1px solid var(--navy-border); border-radius:8px; padding:1rem; font-size:0.9rem; line-height:1.6; max-height:220px; overflow-y:auto; white-space:pre-wrap;" id="modal-full-text">
        </div>
      </div>

      <!-- Indicators List -->
      <div class="indicators-wrap" style="margin-bottom:1rem;">
        <div style="font-size:0.78rem; font-weight:700; text-transform:uppercase; color:var(--text-dim); margin-bottom:0.5rem;">
          Explainable Heuristic Warning Indicators (${indicators.length})
        </div>
        <div class="indicators-list" id="modal-indicators-list">
        </div>
      </div>
    `;

    // Safe text insertion
    const textContainer = modalBody.querySelector("#modal-full-text");
    if (textContainer) textContainer.textContent = textContent;

    const indContainer = modalBody.querySelector("#modal-indicators-list");
    if (indContainer) {
      if (indicators.length > 0) {
        indicators.forEach(tag => {
          const span = document.createElement("span");
          span.className = "tag-badge";
          span.textContent = `⚠️ ${tag}`;
          indContainer.appendChild(span);
        });
      } else {
        const span = document.createElement("span");
        span.className = "tag-badge";
        span.style.background = "rgba(255,255,255,0.05)";
        span.style.borderColor = "var(--navy-border)";
        span.style.color = "var(--text-dim)";
        span.textContent = "No heuristic scam triggers flagged";
        indContainer.appendChild(span);
      }
    }

    modalBackdrop.style.display = "flex";
    setTimeout(() => modalBackdrop.classList.add("active"), 10);
  }

  function closeModal() {
    modalBackdrop.classList.remove("active");
    setTimeout(() => {
      modalBackdrop.style.display = "none";
      activeRecordInModal = null;
    }, 250);
  }

  btnCloseModal.addEventListener("click", closeModal);
  btnDismissModal.addEventListener("click", closeModal);
  modalBackdrop.addEventListener("click", e => {
    if (e.target === modalBackdrop) closeModal();
  });

  // Modal Download PDF
  modalBtnDownloadPdf.addEventListener("click", async () => {
    if (!activeRecordInModal) return;
    const r = activeRecordInModal;
    const isCall = r.record_type === "call" || r.message_type === "call";

    modalBtnDownloadPdf.disabled = true;
    modalBtnDownloadPdf.classList.add("loading");

    try {
      const endpoint = isCall
        ? cfg.ENDPOINTS.downloadCallReportById(r.id)
        : cfg.ENDPOINTS.downloadReportById(r.id);

      const blob = await apiFetch(endpoint);
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = downloadUrl;
      a.download = `ScamShield_${isCall ? "CallAudit" : "Report"}_${r.id}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(downloadUrl);
      toast(`Downloaded PDF report for #${r.id}`, "success");
    } catch (err) {
      toast(`Download failed: ${err.message}`, "error");
    } finally {
      modalBtnDownloadPdf.disabled = false;
      modalBtnDownloadPdf.classList.remove("loading");
    }
  });

  // Clear All History
  btnClearAll.addEventListener("click", async () => {
    if (!confirm("⚠️ WARNING: This will permanently delete your entire scan and audio call analysis history archive. Continue?")) return;

    try {
      await apiFetch(cfg.ENDPOINTS.clearAllHistory, { method: "DELETE" });
      toast("All analysis records cleared from archive.", "info");
      loadHistory();
    } catch (err) {
      toast(`Failed to clear history: ${err.message}`, "error");
    }
  });

  // Initial load
  loadHistory();
})();
