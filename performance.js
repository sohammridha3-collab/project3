/* ==========================================================================
   ScamShield AI — Model Performance Controller
   Fetches live model evaluation metrics and specifications from FastAPI
   ========================================================================== */

(function () {
  "use strict";

  const { apiFetch, cfg } = window.ScamShield;

  async function loadPerformanceSpecs() {
    try {
      const info = await apiFetch(cfg.ENDPOINTS.modelInfo);
      if (info) {
        if (info.classifier_type) {
          const el = document.getElementById("spec-clf");
          if (el) el.textContent = info.classifier_type;
        }
        if (info.vocabulary_sizes) {
          const wordEl = document.getElementById("spec-word-vocab");
          const charEl = document.getElementById("spec-char-vocab");
          if (wordEl && info.vocabulary_sizes.word_tfidf) {
            wordEl.textContent = info.vocabulary_sizes.word_tfidf.toLocaleString();
          }
          if (charEl && info.vocabulary_sizes.char_tfidf) {
            charEl.textContent = info.vocabulary_sizes.char_tfidf.toLocaleString();
          }
        }
      }
    } catch (_) {
      // Gracefully retain pre-rendered static benchmarks if backend endpoint is unavailable
    }
  }

  loadPerformanceSpecs();
})();
