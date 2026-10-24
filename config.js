/* ==========================================================================
   Centralized Frontend API Configuration for ScamShield AI
   Deployed Render Backend: https://project3-backend-fzlv.onrender.com
   ========================================================================== */

const API_BASE_URL = "https://project3-backend-fzlv.onrender.com";

// Expose globally for direct access or non-module scripts
if (typeof window !== "undefined") {
  window.API_BASE_URL = API_BASE_URL;
}

(function () {
  "use strict";

  /**
   * Resolves the active backend API base URL:
   * 1. Window global override (e.g. window.SCAMSHIELD_API_BASE_URL)
   * 2. HTML <meta name="scamshield-api-url" content="...">
   * 3. LocalStorage persistence (set via SCAMSHIELD_CONFIG.setBackendUrl("https://..."))
   * 4. Unified backend host detection (if static files are served directly by the backend itself)
   * 5. Default: Deployed Render backend (API_BASE_URL)
   */
  function resolveApiBaseUrl() {
    // 1. Explicit window override
    if (typeof window.SCAMSHIELD_API_BASE_URL === "string" && window.SCAMSHIELD_API_BASE_URL.trim()) {
      return window.SCAMSHIELD_API_BASE_URL.trim().replace(/\/+$/, "");
    }
    if (typeof window.API_BASE_URL === "string" && window.API_BASE_URL.trim() && window.API_BASE_URL !== API_BASE_URL) {
      return window.API_BASE_URL.trim().replace(/\/+$/, "");
    }

    // 2. Meta tag override
    const metaTag = document.querySelector('meta[name="scamshield-api-url"]');
    if (metaTag && metaTag.content && metaTag.content.trim()) {
      return metaTag.content.trim().replace(/\/+$/, "");
    }

    // 3. LocalStorage override
    try {
      const storedUrl = localStorage.getItem("scamshield_api_base_url");
      if (storedUrl && storedUrl.trim()) {
        return storedUrl.trim().replace(/\/+$/, "");
      }
    } catch (_) {}

    // 4. Host environment detection
    if (typeof window !== "undefined" && window.location) {
      const origin = window.location.origin || "";
      const hostname = window.location.hostname || "";
      const port = window.location.port || "";
      const protocol = window.location.protocol || "";

      // 4a. If served directly by backend on Render
      if (origin === API_BASE_URL || hostname === "project3-backend-fzlv.onrender.com") {
        return origin;
      }

      // 4b. If served directly by local backend (e.g. port 8001 or 8000)
      if (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "0.0.0.0") {
        if (port === "8001" || port === "8000") {
          return origin;
        }
        // If served by Live Server (e.g. 5500, 3000, 5173), prefer local backend on 8001
        return "http://127.0.0.1:8001";
      }

      // 4c. If opened via file:// protocol
      if (protocol === "file:") {
        return "http://127.0.0.1:8001";
      }
    }

    // 5. Default: Connect all static frontend deployments directly to the deployed Render backend
    return API_BASE_URL;
  }

  const resolvedBaseUrl = resolveApiBaseUrl();

  window.SCAMSHIELD_CONFIG = Object.freeze({
    API_BASE_URL: resolvedBaseUrl,
    setBackendUrl: function (url) {
      if (url && typeof url === "string") {
        const clean = url.trim().replace(/\/+$/, "");
        localStorage.setItem("scamshield_api_base_url", clean);
        console.info("[ScamShield AI] Backend URL set to: " + clean);
        window.location.reload();
      }
    },
    resetBackendUrl: function () {
      localStorage.removeItem("scamshield_api_base_url");
      console.info("[ScamShield AI] Reset backend URL to default: " + API_BASE_URL);
      window.location.reload();
    },
    getBackendUrl: function () {
      return resolveApiBaseUrl();
    },
    ENDPOINTS: Object.freeze({
      // Inference
      predict: "/predict",
      batchPredict: "/predict/batch",
      // System & Model
      health: "/health",
      modelInfo: "/model/info",
      modelMetrics: "/model/metrics",
      // Authentication
      register: "/api/auth/register",
      login: "/api/auth/login",
      me: "/api/auth/me",
      // User Scans & Reports
      history: "/api/scans/history",
      stats: "/api/scans/stats",
      deleteScan: function (id) { return `/api/scans/${id}`; },
      clearAllHistory: "/api/scans/clear-all",
      downloadReportById: function (id) { return `/api/scans/${id}/report.pdf`; },
      downloadCustomReport: "/api/report/download",
      // CallScam Audio AI
      callScamAnalyze: "/api/callscam/analyze",
      downloadCallReportById: function (id) { return `/api/callscam/${id}/report.pdf`; },
      downloadCustomCallReport: "/api/callscam/report/download",
      deleteCallRecord: function (id) { return `/api/callscam/${id}`; },
      // URL Scanner
      urlScan: "/api/url-scan"
    }),
    REQUEST_TIMEOUT_MS: 60000,
    MAX_CHARS: 20000
  });
})();
