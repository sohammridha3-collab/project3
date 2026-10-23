/* ==========================================================================
   ScamShield AI — Main Shared JavaScript Core
   Header/Footer Injection, Auth State Management, API Client, and UI Helpers
   ========================================================================== */

(function () {
  "use strict";

  const cfg = window.SCAMSHIELD_CONFIG;

  // DOM creation helper
  function el(tag, attrs, kids) {
    const node = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => {
      if (k === "class") node.className = v;
      else if (k.startsWith("data-") || k.startsWith("aria-")) node.setAttribute(k, v);
      else node[k] = v;
    });
    (kids || []).forEach(k => {
      if (typeof k === "string") node.appendChild(document.createTextNode(k));
      else if (k instanceof Node) node.appendChild(k);
    });
    return node;
  }

  // Auth token & user storage
  const TOKEN_KEY = "scamshield_token";
  const USER_KEY = "scamshield_user";

  function getToken() {
    return localStorage.getItem(TOKEN_KEY);
  }

  function getUser() {
    try {
      const u = localStorage.getItem(USER_KEY);
      return u ? JSON.parse(u) : null;
    } catch (_) {
      return null;
    }
  }

  function setAuth(token, user) {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  }

  function logout() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    window.location.href = "login.html";
  }

  function requireAuth() {
    if (!getToken()) {
      const returnUrl = encodeURIComponent(window.location.pathname.split("/").pop() || "dashboard.html");
      window.location.href = `login.html?return=${returnUrl}`;
    }
  }

  // Toast Notification System
  function toast(message, type = "info") {
    let container = document.getElementById("toast-container");
    if (!container) {
      container = el("div", { id: "toast-container", class: "toast-container" });
      document.body.appendChild(container);
    }
    const icon = type === "error" ? "❌" : type === "success" ? "✅" : "ℹ️";
    const t = el("div", { class: `toast ${type}` }, [
      el("span", {}, [icon]),
      el("span", {}, [message])
    ]);
    container.appendChild(t);
    setTimeout(() => {
      t.style.opacity = "0";
      t.style.transition = "opacity 0.3s ease";
      setTimeout(() => t.remove(), 300);
    }, 4000);
  }

  // API Client with timeout, auth token injection, and structured error handling
  class ApiError extends Error {
    constructor(status, detail) {
      super(detail || `API error ${status}`);
      this.status = status;
      this.detail = detail;
    }
  }

  async function apiFetch(endpoint, options = {}) {
    const defaultApiUrl = (typeof window !== "undefined" && window.API_BASE_URL)
      ? window.API_BASE_URL
      : "https://project3-backend-fzlv.onrender.com";
    const baseUrl = (cfg && cfg.API_BASE_URL) ? cfg.API_BASE_URL.replace(/\/+$/, "") : defaultApiUrl;
    const url = endpoint.startsWith("http") ? endpoint : `${baseUrl}${endpoint}`;
    const token = getToken();
    const headers = {
      ...(options.headers || {})
    };

    let body = options.body;
    if (body !== undefined && body !== null) {
      if (typeof FormData !== "undefined" && body instanceof FormData) {
        // FormData automatically handles its own multipart boundary; leave as is
      } else if (typeof Blob !== "undefined" && body instanceof Blob) {
        // Binary blob body
      } else if (typeof ArrayBuffer !== "undefined" && body instanceof ArrayBuffer) {
        // Binary buffer body
      } else if (typeof body === "object") {
        // Plain JavaScript object: MUST be serialized with JSON.stringify() to avoid "[object Object]"
        body = JSON.stringify(body);
        if (!headers["Content-Type"]) {
          headers["Content-Type"] = "application/json";
        }
      } else if (typeof body === "string") {
        // Already serialized JSON or text
        if (!headers["Content-Type"]) {
          headers["Content-Type"] = "application/json";
        }
      }
    }

    if (token && !headers["Authorization"]) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), (cfg && cfg.REQUEST_TIMEOUT_MS) || 60000);

    async function executeFetch(requestUrl) {
      const response = await fetch(requestUrl, {
        ...options,
        headers,
        body,
        signal: controller.signal
      });

      // Handle binary responses (e.g. PDF downloads)
      const contentType = response.headers.get("content-type") || "";
      if (contentType.includes("application/pdf")) {
        if (!response.ok) throw new ApiError(response.status, "Failed to download PDF report");
        return await response.blob();
      }

      // Handle JSON responses
      let data = null;
      try {
        data = await response.json();
      } catch (_) {
        /* Non-JSON response */
      }

      if (!response.ok) {
        let detail = "An error occurred with the server request.";
        if (data) {
          if (typeof data.detail === "string") {
            detail = data.detail;
          } else if (Array.isArray(data.detail)) {
            detail = data.detail.map(d => {
              if (typeof d === "string") return d;
              if (d && d.msg) {
                const loc = Array.isArray(d.loc) ? d.loc.filter(l => l !== "body").join(".") : "";
                return loc ? `${loc}: ${d.msg}` : d.msg;
              }
              return JSON.stringify(d);
            }).join("; ");
          } else if (data.message) {
            detail = data.message;
          }
        }
        throw new ApiError(response.status, detail);
      }

      return data;
    }

    try {
      const data = await executeFetch(url);
      clearTimeout(timeout);
      return data;
    } catch (err) {
      clearTimeout(timeout);
      if (err.name === "AbortError") {
        throw new ApiError(408, "The server took too long to respond. The Render backend may be waking up from sleep (cold start). Please wait a moment and try again.");
      }
      if (err instanceof ApiError) throw err;
      const targetHost = baseUrl || "https://project3-backend-fzlv.onrender.com";
      throw new ApiError(0, `Cannot connect to ScamShield API at ${targetHost}. If the Render backend is waking up, please wait a few seconds and try again.`);
    }
  }

  // Dynamic Header & Navigation Rendering
  function setupHeader() {
    const header = document.getElementById("site-header");
    if (!header) return;

    const currentFile = location.pathname.split("/").pop() || "index.html";
    const user = getUser();

    header.innerHTML = "";
    const wrap = el("div", { class: "wrap header-bar" });

    // Brand logo
    const brandLink = el("a", { href: "index.html", class: "brand" }, [
      el("div", { class: "brand-shield" }),
      el("span", {}, ["ScamShield", el("span", { style: "color:var(--cyan);font-weight:400;" }, ["AI"])])
    ]);

    // Navigation links
    const nav = el("nav", { class: "nav-links", id: "nav-links" });

    const basePages = [
      ["index.html", "Home"],
      ["analyze.html", "Analyze"],
      ["callscam.html", "CallScam"],
      ["details.html", "Details"]
    ];

    basePages.forEach(([file, label]) => {
      const a = el("a", { href: file }, [label]);
      if (currentFile === file) a.setAttribute("aria-current", "page");
      nav.appendChild(a);
    });

    if (user) {
      const dashLink = el("a", { href: "dashboard.html" }, ["Results"]);
      if (currentFile === "dashboard.html") dashLink.setAttribute("aria-current", "page");
      nav.appendChild(dashLink);

      const histLink = el("a", { href: "history.html" }, ["History"]);
      if (currentFile === "history.html") histLink.setAttribute("aria-current", "page");
      nav.appendChild(histLink);
    }

    // Right-side Auth buttons
    const authBox = el("div", { class: "nav-auth" });
    if (user) {
      const initial = (user.full_name || user.email || "U").charAt(0).toUpperCase();
      const badge = el("div", { class: "user-badge" }, [
        el("span", { class: "user-badge-avatar" }, [initial]),
        el("span", {}, [user.full_name || user.email])
      ]);
      const logoutBtn = el("button", { class: "btn btn-ghost btn-sm" }, ["Sign Out"]);
      logoutBtn.addEventListener("click", logout);
      authBox.appendChild(badge);
      authBox.appendChild(logoutBtn);
    } else {
      const loginBtn = el("a", { href: "login.html", class: "btn btn-ghost btn-sm" }, ["Log In"]);
      const regBtn = el("a", { href: "register.html", class: "btn btn-primary btn-sm" }, ["Register"]);
      authBox.appendChild(loginBtn);
      authBox.appendChild(regBtn);
    }

    // Mobile hamburger toggle
    const toggle = el("button", { class: "nav-toggle", "aria-label": "Toggle Menu" }, ["☰"]);
    toggle.addEventListener("click", () => {
      nav.classList.toggle("open");
    });

    wrap.appendChild(brandLink);
    wrap.appendChild(nav);
    wrap.appendChild(authBox);
    wrap.appendChild(toggle);
    header.appendChild(wrap);
  }

  // Dynamic Footer Rendering
  function setupFooter() {
    const footer = document.getElementById("site-footer");
    if (!footer) return;

    footer.innerHTML = "";
    const wrap = el("div", { class: "wrap" });

    const grid = el("div", { class: "footer-grid" }, [
      el("div", { class: "footer-col" }, [
        el("div", { class: "brand", style: "margin-bottom:1rem;" }, [
          el("div", { class: "brand-shield" }),
          el("span", {}, ["ScamShield", el("span", { style: "color:var(--cyan);" }, ["AI"])])
        ]),
        el("p", { style: "font-size:0.88rem;max-width:40ch;" }, [
          "AI-powered scam, phishing, and call fraud screening system developed for B.Tech CSE capstone. Trained on the CEAS corpus with multilingual audio intelligence."
        ])
      ]),
      el("div", { class: "footer-col" }, [
        el("h4", {}, ["Navigation"]),
        el("ul", {}, [
          el("li", {}, [el("a", { href: "analyze.html" }, ["Analyze Message"])]),
          el("li", {}, [el("a", { href: "callscam.html" }, ["CallScam Detection"])]),
          el("li", {}, [el("a", { href: "details.html#overview" }, ["Project Overview"])]),
          el("li", {}, [el("a", { href: "details.html#how-it-works" }, ["How It Works"])]),
          el("li", {}, [el("a", { href: "details.html#performance" }, ["Model Performance"])]),
          el("li", {}, [el("a", { href: "details.html#privacy" }, ["Privacy & Limitations"])])
        ])
      ]),
      el("div", { class: "footer-col" }, [
        el("h4", {}, ["Developer & System"]),
        el("ul", {}, [
          el("li", {}, [el("a", { href: `${cfg.API_BASE_URL}/docs`, target: "_blank" }, ["FastAPI Swagger Docs"])]),
          el("li", {}, [el("a", { href: `${cfg.API_BASE_URL}/redoc`, target: "_blank" }, ["ReDoc Specification"])]),
          el("li", {}, [el("a", { href: `${cfg.API_BASE_URL}/health`, target: "_blank" }, ["Live Backend Health"])])
        ])
      ])
    ]);

    const bottom = el("div", { class: "footer-bottom" }, [
      el("span", {}, ["© 2026 ScamShield AI • Academic Machine Learning Project."]),
      el("span", { style: "color:var(--text-dim);" }, [
        "Statistical estimates only. Always verify sensitive financial or credential requests directly."
      ])
    ]);

    wrap.appendChild(grid);
    wrap.appendChild(bottom);
    footer.appendChild(wrap);
  }

  // 3D Card tilt micro-interaction
  function setupTilt() {
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduceMotion) return;

    document.querySelectorAll(".tilt").forEach(card => {
      card.addEventListener("mousemove", e => {
        const rect = card.getBoundingClientRect();
        const x = (e.clientX - rect.left) / rect.width - 0.5;
        const y = (e.clientY - rect.top) / rect.height - 0.5;
        card.style.transform = `perspective(800px) rotateX(${(-y * 6).toFixed(2)}deg) rotateY(${(x * 8).toFixed(2)}deg) translateY(-4px)`;
      });
      card.addEventListener("mouseleave", () => {
        card.style.transform = "";
      });
    });
  }

  // Timestamp formatting: parses unambiguous UTC ISO string and converts to local browser time
  function parseUtcDate(dateVal) {
    if (!dateVal) return null;
    let isoStr = typeof dateVal === "string" ? dateVal.trim() : dateVal;
    if (typeof isoStr === "string") {
      // If no timezone offset is present (no trailing 'Z' and no +/-HH:MM), treat as UTC and append 'Z'
      if (!isoStr.endsWith("Z") && !/[+-]\d{2}:?\d{2}$/.test(isoStr)) {
        isoStr = isoStr.replace(" ", "T") + "Z";
      }
    }
    const d = new Date(isoStr);
    return isNaN(d.getTime()) ? null : d;
  }

  function formatDateTime(dateVal) {
    const d = parseUtcDate(dateVal);
    if (!d) return "N/A";

    const day = d.getDate();
    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const month = months[d.getMonth()];
    const year = d.getFullYear();
    let hours = d.getHours();
    const minutes = String(d.getMinutes()).padStart(2, "0");
    const ampm = hours >= 12 ? "PM" : "AM";
    hours = hours % 12;
    hours = hours ? hours : 12;
    return `${day} ${month} ${year}, ${hours}:${minutes} ${ampm}`;
  }

  function formatRelativeTime(dateVal) {
    const d = parseUtcDate(dateVal);
    if (!d) return "";
    const now = new Date();
    const diffSec = Math.floor((now.getTime() - d.getTime()) / 1000);
    if (diffSec < 0 && diffSec > -10) return "just now";
    if (diffSec < 45) return "just now";
    if (diffSec < 90) return "1 minute ago";
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)} minutes ago`;
    if (diffSec < 7200) return "1 hour ago";
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)} hours ago`;
    if (diffSec < 172800) return "yesterday";
    return `${Math.floor(diffSec / 86400)} days ago`;
  }

  // Initialize
  document.addEventListener("DOMContentLoaded", () => {
    setupHeader();
    setupFooter();
    setupTilt();
  });

  // Global namespace export
  window.ScamShield = {
    cfg,
    el,
    apiFetch,
    ApiError,
    getToken,
    getUser,
    setAuth,
    logout,
    requireAuth,
    toast,
    parseUtcDate,
    formatDateTime,
    formatRelativeTime
  };
})();

