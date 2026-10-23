/* Centralized Frontend Configuration for ScamShield AI */
(function () {
  "use strict";

  /**
   * Resolves the deployed FastAPI backend URL with robust priority:
   * 1. Window global override (e.g. window.SCAMSHIELD_API_BASE_URL or window.API_BASE_URL)
   * 2. HTML <meta name="scamshield-api-url" content="...">
   * 3. localStorage override (set via SCAMSHIELD_CONFIG.setBackendUrl("https://..."))
   * 4. Automatic inference:
   *    - file:// -> "http://127.0.0.1:8001"
   *    - Local development (localhost / 127.0.0.1) on non-8001 port -> "http://127.0.0.1:8001"
   *    - Full-stack production (Render, Railway, Heroku, Docker, VPS, custom domain) -> window.location.origin
   *    - Static-only hosts (GitHub Pages, Vercel, Netlify) -> warn & fallback
   */
  function resolveApiBaseUrl() {
    // 1. Window global override
    if (typeof window.SCAMSHIELD_API_BASE_URL === "string" && window.SCAMSHIELD_API_BASE_URL.trim()) {
      return window.SCAMSHIELD_API_BASE_URL.trim().replace(/\/+$/, "");
    }
    if (typeof window.API_BASE_URL === "string" && window.API_BASE_URL.trim()) {
      return window.API_BASE_URL.trim().replace(/\/+$/, "");
    }

    // 2. Meta tag override
    const metaTag = document.querySelector('meta[name="scamshield-api-url"]');
    if (metaTag && metaTag.content && metaTag.content.trim()) {
      return metaTag.content.trim().replace(/\/+$/, "");
    }

    // 3. LocalStorage persistence
    try {
      const storedUrl = localStorage.getItem("scamshield_api_base_url");
      if (storedUrl && storedUrl.trim()) {
        return storedUrl.trim().replace(/\/+$/, "");
      }
    } catch (_) {}

    // 4. Inferred from current browser location
    const protocol = window.location.protocol;
    const hostname = window.location.hostname;
    const port = window.location.port;

    // Local file testing
    if (protocol === "file:") {
      return "http://127.0.0.1:8001";
    }

    // Local development server (e.g. VS Code Live Server on 5500, Vite on 5173, etc.)
    const isLocalhost = hostname === "localhost" || hostname === "127.0.0.1" || hostname === "0.0.0.0";
    if (isLocalhost) {
      if (port === "8001") {
        return window.location.origin;
      }
      return "http://127.0.0.1:8001";
    }

    // Static-only hosting platforms (when frontend is deployed separately without backend)
    const isStaticHost =
      hostname.endsWith("github.io") ||
      hostname.endsWith("vercel.app") ||
      hostname.endsWith("netlify.app") ||
      hostname.endsWith("pages.dev") ||
      hostname.endsWith("firebaseapp.com") ||
      hostname.endsWith("surge.sh");

    if (isStaticHost) {
      console.warn(
        "[ScamShield AI] Running on static host (" + hostname + "). " +
        "If requests fail, set your deployed FastAPI backend URL using: " +
        "window.SCAMSHIELD_CONFIG.setBackendUrl('https://your-backend.onrender.com')"
      );
      return "";
    }

    // Default for unified full-stack deployments (Render, Railway, Heroku, Docker, custom domains)
    // The FastAPI backend directly serves the frontend pages on the same origin.
    return window.location.origin;
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
      deleteScan: id => `/api/scans/${id}`,
      clearAllHistory: "/api/scans/clear-all",
      downloadReportById: id => `/api/scans/${id}/report.pdf`,
      downloadCustomReport: "/api/report/download",
      // CallScam
      callScamAnalyze: "/api/callscam/analyze",
      downloadCallReportById: id => `/api/callscam/${id}/report.pdf`,
      downloadCustomCallReport: "/api/callscam/report/download",
      deleteCallRecord: id => `/api/callscam/${id}`
    }),
    REQUEST_TIMEOUT_MS: 30000,
    MAX_CHARS: 20000
  });
})();
