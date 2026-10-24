/* ==========================================================================
   Centralized Frontend API Configuration for ScamShield AI
   Production Backend: https://project3-backend-fzlv.onrender.com
   ========================================================================== */

const PRODUCTION_API_BASE_URL = "https://project3-backend-fzlv.onrender.com";

// Expose globally for direct access or non-module scripts
if (typeof window !== "undefined") {
  window.PRODUCTION_API_BASE_URL = PRODUCTION_API_BASE_URL;
  window.API_BASE_URL = PRODUCTION_API_BASE_URL;
}

(function () {
  "use strict";

  /**
   * Resolves the active backend API base URL following strict priority:
   * 1. Window environment variable overrides:
   *    - window.__ENV__?.VITE_API_BASE_URL
   *    - window.VITE_API_BASE_URL
   *    - window.SCAMSHIELD_API_BASE_URL
   * 2. HTML <meta name="scamshield-api-url" content="...">
   * 3. LocalStorage persistence (set via SCAMSHIELD_CONFIG.setBackendUrl("https://..."))
   * 4. Local development host detection (localhost / 127.0.0.1) -> http://127.0.0.1:8001
   * 5. Production Default: https://project3-backend-fzlv.onrender.com (NEVER localhost in production)
   */
  function resolveApiBaseUrl() {
    // 1. Environment variable overrides (Vite / bundler / runtime script injection)
    if (typeof window !== "undefined") {
      if (window.__ENV__ && typeof window.__ENV__.VITE_API_BASE_URL === "string" && window.__ENV__.VITE_API_BASE_URL.trim()) {
        return window.__ENV__.VITE_API_BASE_URL.trim().replace(/\/+$/, "");
      }
      if (typeof window.VITE_API_BASE_URL === "string" && window.VITE_API_BASE_URL.trim()) {
        return window.VITE_API_BASE_URL.trim().replace(/\/+$/, "");
      }
      if (typeof window.SCAMSHIELD_API_BASE_URL === "string" && window.SCAMSHIELD_API_BASE_URL.trim()) {
        return window.SCAMSHIELD_API_BASE_URL.trim().replace(/\/+$/, "");
      }
    }

    // 2. Meta tag override in HTML <head>
    if (typeof document !== "undefined") {
      const metaTag = document.querySelector('meta[name="scamshield-api-url"]');
      if (metaTag && metaTag.content && metaTag.content.trim()) {
        return metaTag.content.trim().replace(/\/+$/, "");
      }
    }

    // 3. LocalStorage user override (for testing or switching environments)
    try {
      if (typeof localStorage !== "undefined") {
        const storedUrl = localStorage.getItem("scamshield_api_base_url");
        if (storedUrl && storedUrl.trim()) {
          return storedUrl.trim().replace(/\/+$/, "");
        }
      }
    } catch (_) {}

    // 4. Host environment detection
    if (typeof window !== "undefined" && window.location) {
      const origin = window.location.origin || "";
      const hostname = (window.location.hostname || "").toLowerCase();
      const port = window.location.port || "";

      // 4a. If frontend is served directly by backend host (Render or local backend)
      if (hostname === "project3-backend-fzlv.onrender.com") {
        return PRODUCTION_API_BASE_URL;
      }
      if (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "0.0.0.0") {
        if (port === "8001" || port === "8000") {
          return origin;
        }
        // If served by local dev server (Live Server on 5500, Vite on 5173, etc.)
        return "http://127.0.0.1:8001";
      }
    }

    // 5. Default: Connect all deployed frontends directly to the deployed Render backend
    return PRODUCTION_API_BASE_URL;
  }

  const resolvedBaseUrl = resolveApiBaseUrl();

  /**
   * Constructs a sanitized, normalized API URL preventing duplicate slashes or duplicate /api prefixes.
   */
  function buildApiUrl(endpoint) {
    const base = resolveApiBaseUrl().replace(/\/+$/, "");
    let path = String(endpoint || "").trim();
    if (!path.startsWith("/")) {
      path = "/" + path;
    }
    // Prevent duplicate /api if base already ends with /api
    if (base.endsWith("/api") && path.startsWith("/api/")) {
      path = path.substring(4);
    }
    return `${base}${path}`;
  }

  const configObject = Object.freeze({
    API_BASE_URL: resolvedBaseUrl,
    PRODUCTION_API_BASE_URL: PRODUCTION_API_BASE_URL,
    resolveApiBaseUrl: resolveApiBaseUrl,
    buildApiUrl: buildApiUrl,
    isLocalDevelopment: function () {
      if (typeof window === "undefined" || !window.location) return false;
      const h = (window.location.hostname || "").toLowerCase();
      return h === "localhost" || h === "127.0.0.1" || h === "0.0.0.0";
    },
    setBackendUrl: function (url) {
      if (url && typeof url === "string") {
        const clean = url.trim().replace(/\/+$/, "");
        localStorage.setItem("scamshield_api_base_url", clean);
        console.info("[ScamShield AI] Backend URL manually set to: " + clean);
        window.location.reload();
      }
    },
    resetBackendUrl: function () {
      localStorage.removeItem("scamshield_api_base_url");
      console.info("[ScamShield AI] Reset backend URL to default: " + PRODUCTION_API_BASE_URL);
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
      readiness: "/health/ready",
      modelInfo: "/model/info",
      modelMetrics: "/model/metrics",
      urlModelInfo: "/api/url-model/info",
      urlModelMetrics: "/api/url-model/metrics",
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

  window.SCAMSHIELD_CONFIG = configObject;
})();
