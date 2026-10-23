/* ==========================================================================
   ScamShield AI — Authentication Client (Login & Register)
   ========================================================================== */

(function () {
  "use strict";

  const { apiFetch, ApiError, setAuth, toast, cfg } = window.ScamShield;

  // Toggle Password Visibility
  document.querySelectorAll(".input-btn-eye").forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-target");
      const input = document.getElementById(targetId);
      if (!input) return;
      if (input.type === "password") {
        input.type = "text";
        btn.textContent = "🙈";
      } else {
        input.type = "password";
        btn.textContent = "👁️";
      }
    });
  });

  // Password Strength Checker
  const pwdInput = document.getElementById("reg-password");
  const strengthFill = document.getElementById("strength-fill");
  const strengthLabel = document.getElementById("strength-label");

  if (pwdInput && strengthFill && strengthLabel) {
    pwdInput.addEventListener("input", () => {
      const val = pwdInput.value;
      let score = 0;
      if (val.length >= 8) score++;
      if (/[A-Z]/.test(val)) score++;
      if (/[0-9]/.test(val)) score++;
      if (/[^A-Za-z0-9]/.test(val)) score++;

      if (val.length === 0) {
        strengthFill.style.width = "0%";
        strengthLabel.textContent = "Enter at least 8 characters";
        strengthLabel.style.color = "var(--text-dim)";
      } else if (score <= 1) {
        strengthFill.style.width = "25%";
        strengthFill.style.background = "#EF4444";
        strengthLabel.textContent = "Weak (requires upper & number)";
        strengthLabel.style.color = "#F87171";
      } else if (score === 2) {
        strengthFill.style.width = "50%";
        strengthFill.style.background = "#F59E0B";
        strengthLabel.textContent = "Moderate (add special character)";
        strengthLabel.style.color = "#FBBF24";
      } else if (score === 3) {
        strengthFill.style.width = "75%";
        strengthFill.style.background = "#3B82F6";
        strengthLabel.textContent = "Good password";
        strengthLabel.style.color = "#93C5FD";
      } else {
        strengthFill.style.width = "100%";
        strengthFill.style.background = "#10B981";
        strengthLabel.textContent = "Strong password";
        strengthLabel.style.color = "#34D399";
      }
    });
  }

  // Handle Registration Form Submission
  const registerForm = document.getElementById("register-form");
  if (registerForm) {
    const errorBox = document.getElementById("auth-error");
    const submitBtn = document.getElementById("reg-submit-btn");

    registerForm.addEventListener("submit", async e => {
      e.preventDefault();
      errorBox.hidden = true;

      const fullName = document.getElementById("reg-fullname").value.trim();
      const email = document.getElementById("reg-email").value.trim();
      const password = document.getElementById("reg-password").value;
      const confirmPassword = document.getElementById("reg-confirm").value;
      const terms = document.getElementById("reg-terms").checked;

      if (!terms) {
        errorBox.textContent = "Please agree to the Terms of Service & Responsible AI Use.";
        errorBox.hidden = false;
        return;
      }

      if (password !== confirmPassword) {
        errorBox.textContent = "Passwords do not match. Please re-enter.";
        errorBox.hidden = false;
        return;
      }

      submitBtn.disabled = true;
      submitBtn.classList.add("loading");

      try {
        const payload = {
          full_name: fullName,
          email: email,
          password: password,
          confirm_password: confirmPassword
        };

        const res = await apiFetch(cfg.ENDPOINTS.register, {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify(payload)
        });

        setAuth(res.access_token, res.user);
        toast(`Account created! Welcome, ${res.user.full_name}`, "success");
        setTimeout(() => {
          window.location.href = "dashboard.html";
        }, 1000);
      } catch (err) {
        errorBox.textContent = err.detail || err.message || "Registration failed.";
        errorBox.hidden = false;
      } finally {
        submitBtn.disabled = false;
        submitBtn.classList.remove("loading");
      }
    });
  }

  // Handle Login Form Submission
  const loginForm = document.getElementById("login-form");
  if (loginForm) {
    const errorBox = document.getElementById("auth-error");
    const submitBtn = document.getElementById("login-submit-btn");

    loginForm.addEventListener("submit", async e => {
      e.preventDefault();
      errorBox.hidden = true;

      const email = document.getElementById("login-email").value.trim();
      const password = document.getElementById("login-password").value;

      submitBtn.disabled = true;
      submitBtn.classList.add("loading");

      try {
        const payload = {
          email: email,
          password: password
        };

        const res = await apiFetch(cfg.ENDPOINTS.login, {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify(payload)
        });

        setAuth(res.access_token, res.user);
        toast(`Signed in as ${res.user.full_name}`, "success");

        // Check for return URL in query parameter
        const params = new URLSearchParams(window.location.search);
        const returnUrl = params.get("return") || "dashboard.html";
        setTimeout(() => {
          window.location.href = returnUrl;
        }, 800);
      } catch (err) {
        errorBox.textContent = err.detail || err.message || "Invalid email or password.";
        errorBox.hidden = false;
      } finally {
        submitBtn.disabled = false;
        submitBtn.classList.remove("loading");
      }
    });
  }
})();
