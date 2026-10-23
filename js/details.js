/* ==========================================================================
   ScamShield AI — Details Page Controller
   Sidebar Navigation ScrollSpy & Tab Highlight
   ========================================================================== */

(function () {
  "use strict";

  const navLinks = document.querySelectorAll(".details-nav-item");
  const sections = document.querySelectorAll(".details-section");

  if (!navLinks.length || !sections.length) return;

  // Click handler for smooth scrolling
  navLinks.forEach(link => {
    link.addEventListener("click", e => {
      e.preventDefault();
      const targetId = link.getAttribute("href").substring(1);
      const targetSec = document.getElementById(targetId);
      if (targetSec) {
        targetSec.scrollIntoView({ behavior: "smooth", block: "start" });
        history.replaceState(null, "", `#${targetId}`);
        setActiveLink(targetId);
      }
    });
  });

  function setActiveLink(id) {
    navLinks.forEach(link => {
      if (link.getAttribute("href") === `#${id}`) {
        link.classList.add("active");
      } else {
        link.classList.remove("active");
      }
    });
  }

  // ScrollSpy with IntersectionObserver
  const observer = new IntersectionObserver(
    entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const id = entry.target.getAttribute("id");
          if (id) {
            setActiveLink(id);
          }
        }
      });
    },
    {
      rootMargin: "-20% 0px -60% 0px",
      threshold: 0
    }
  );

  sections.forEach(sec => observer.observe(sec));

  // Handle initial hash in URL
  if (window.location.hash) {
    const initialId = window.location.hash.substring(1);
    const target = document.getElementById(initialId);
    if (target) {
      setTimeout(() => {
        target.scrollIntoView({ behavior: "smooth" });
        setActiveLink(initialId);
      }, 200);
    }
  }
})();
