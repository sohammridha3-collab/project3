/* ==========================================================================
   ScamShield AI — User Dashboard Controller
   ========================================================================== */

(function () {
  "use strict";

  const { apiFetch, requireAuth, getUser, toast, cfg, formatDateTime, formatRelativeTime } = window.ScamShield;

  // Protect page: require login
  requireAuth();

  const user = getUser();
  if (user) {
    document.getElementById("welcome-msg").textContent = "Results";
    document.getElementById("user-email-subtitle").textContent = `Welcome, ${user.full_name} (${user.email}) • Personal Security Operations`;
  }

  const statTotal = document.getElementById("stat-total");
  const statScam = document.getElementById("stat-scam");
  const statClean = document.getElementById("stat-clean");
  const statRatio = document.getElementById("stat-ratio");

  const emptyBox = document.getElementById("history-empty");
  const tableWrap = document.getElementById("history-table-wrap");
  const tbody = document.getElementById("history-tbody");

  async function loadDashboard() {
    try {
      const stats = await apiFetch(cfg.ENDPOINTS.stats);

      statTotal.textContent = stats.total_scans;
      statScam.textContent = stats.scam_count;
      statClean.textContent = stats.legitimate_count;
      statRatio.textContent = `${stats.scam_percentage}%`;

      const scans = stats.recent_scans || [];
      if (scans.length === 0) {
        emptyBox.style.display = "block";
        tableWrap.style.display = "none";
        return;
      }

      emptyBox.style.display = "none";
      tableWrap.style.display = "block";
      tbody.innerHTML = "";

      scans.forEach(scan => {
        const tr = document.createElement("tr");

        // Format Date consistently using user local timezone (e.g. 23 Oct 2026, 3:27 PM)
        const dateStr = formatDateTime(scan.created_at);
        const relTime = formatRelativeTime(scan.created_at);

        const isCall = scan.record_type === "call" || scan.message_type === "call";
        const isScam = scan.is_scam;

        // Content preview
        const rawContent = scan.message_text || scan.transcript || "";
        const preview = rawContent.length > 70
          ? rawContent.substring(0, 67) + "..."
          : rawContent;

        const secondaryInfo = isCall
          ? (scan.audio_filename ? `🎧 ${scan.audio_filename}` : "🎙️ Call Recording")
          : (scan.subject ? `Subj: ${scan.subject.substring(0, 35)}` : "");

        tr.innerHTML = `
          <td style="white-space:nowrap; font-size:0.85rem;">
            <div style="font-weight:600; color:var(--text);">${dateStr}</div>
            ${relTime ? `<div style="font-size:0.75rem; color:var(--text-dim); margin-top:2px;">${relTime}</div>` : ""}
          </td>
          <td>
            <span style="font-size:0.75rem; padding:2px 8px; border-radius:6px; font-weight:600; display:inline-flex; align-items:center; gap:4px; ${isCall ? "background:rgba(139,92,246,0.15); color:#C4B5FD; border:1px solid rgba(139,92,246,0.3);" : "background:rgba(59,130,246,0.15); color:#93C5FD; border:1px solid rgba(59,130,246,0.3);"}">
              ${isCall ? "🎙️ Call" : "📩 Message"}
            </span>
          </td>
          <td style="max-width:300px; font-weight:500;">
            <div class="dash-preview-text" style="text-overflow:ellipsis; overflow:hidden; white-space:nowrap;"></div>
            ${secondaryInfo ? `<div style="font-size:0.75rem; color:var(--text-dim); margin-top:2px;">${secondaryInfo}</div>` : ""}
          </td>
          <td>
            <span class="status-pill ${isScam ? "scam" : "safe"}">
              ${isScam ? "🚨 Threat" : "✅ Clean"}
            </span>
          </td>
          <td style="font-family:var(--font-mono); font-weight:600; font-size:0.88rem;">
            ${scan.confidence_percentage}
          </td>
          <td>
            <button type="button" class="btn btn-ghost btn-sm download-btn" data-id="${scan.id}" data-type="${isCall ? "call" : "message"}" title="Download Audit PDF Report">
              📄 PDF
            </button>
          </td>
        `;

        // Safe textContent assignment
        tr.querySelector(".dash-preview-text").textContent = preview;

        // Wire download button
        const dlBtn = tr.querySelector(".download-btn");
        dlBtn.addEventListener("click", () => downloadReport(scan.id, isCall ? "call" : "message", dlBtn));

        tbody.appendChild(tr);
      });
    } catch (err) {
      toast(`Failed to load results statistics: ${err.message}`, "error");
    }
  }

  async function downloadReport(scanId, recordType, btn) {
    btn.disabled = true;
    btn.classList.add("loading");

    try {
      const endpoint = recordType === "call"
        ? `${cfg.API_BASE_URL}/api/callscam/${scanId}/report.pdf`
        : cfg.ENDPOINTS.downloadReportById(scanId);

      const blob = await apiFetch(endpoint);
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = downloadUrl;
      a.download = `ScamShield_${recordType === "call" ? "CallAudit" : "Report"}_${scanId}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(downloadUrl);
      toast(`Report for Scan #${scanId} downloaded!`, "success");
    } catch (err) {
      toast(`Download error: ${err.message}`, "error");
    } finally {
      btn.disabled = false;
      btn.classList.remove("loading");
    }
  }

  loadDashboard();

})();
