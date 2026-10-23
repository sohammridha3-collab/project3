/* Centralized Frontend Configuration for ScamShield AI */
(function () {
  "use strict";

  // If page is served directly by FastAPI on port 8001, use origin;
  // otherwise (Live Server, file://, port 5500/8080/etc.), route all API requests to http://127.0.0.1:8001
  const isDirectBackend = window.location.port === "8001";
  const defaultBaseUrl = isDirectBackend ? window.location.origin : "http://127.0.0.1:8001";

  window.SCAMSHIELD_CONFIG = Object.freeze({
    API_BASE_URL: defaultBaseUrl,
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
    REQUEST_TIMEOUT_MS: 20000,
    MAX_CHARS: 20000
  });
})();
