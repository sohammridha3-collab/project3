/* ==========================================================================
   ScamShield AI — Futuristic 3D Cyber Security Core (Three.js WebGL)
   Renders a cinematic rotating cyber-shield ring core with luminous red &
   orange orbiting particles, dynamic lighting, and mouse-parallax interaction.
   ========================================================================== */

(function () {
  "use strict";

  function initCyberHero() {
    const container = document.getElementById("hero-3d-canvas-container");
    if (!container) return;

    // Check if Three.js is loaded
    if (typeof THREE === "undefined") {
      console.warn("[ScamShield 3D] Three.js not found. Using CSS holographic fallback.");
      return;
    }

    // Check WebGL availability
    function isWebGLAvailable() {
      try {
        const canvas = document.createElement("canvas");
        return !!(window.WebGLRenderingContext && (canvas.getContext("webgl") || canvas.getContext("experimental-webgl")));
      } catch (_) {
        return false;
      }
    }

    if (!isWebGLAvailable()) {
      console.warn("[ScamShield 3D] WebGL not supported in this browser environment.");
      return;
    }

    const width = container.clientWidth || 480;
    const height = container.clientHeight || 480;

    // 1. Scene, Camera, Renderer
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.z = 6.2;

    const renderer = new THREE.WebGLRenderer({
      alpha: true,
      antialias: true,
      powerPreference: "high-performance"
    });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setClearColor(0x000000, 0);

    // Clear any previous canvas
    container.innerHTML = "";
    container.appendChild(renderer.domElement);
    renderer.domElement.style.width = "100%";
    renderer.domElement.style.height = "100%";
    renderer.domElement.style.display = "block";

    // 2. Main Cyber Shield Group
    const coreGroup = new THREE.Group();
    scene.add(coreGroup);

    // 2a. Inner Central Security Core (Wireframe Icosahedron)
    const innerGeom = new THREE.IcosahedronGeometry(1.05, 1);
    const innerMat = new THREE.MeshBasicMaterial({
      color: 0xFF1E43,
      wireframe: true,
      transparent: true,
      opacity: 0.85
    });
    const innerCore = new THREE.Mesh(innerGeom, innerMat);
    coreGroup.add(innerCore);

    // 2b. Solid Glowing Core Sphere
    const glowSphereGeom = new THREE.SphereGeometry(0.72, 32, 32);
    const glowSphereMat = new THREE.MeshBasicMaterial({
      color: 0x99001A,
      transparent: true,
      opacity: 0.55
    });
    const glowSphere = new THREE.Mesh(glowSphereGeom, glowSphereMat);
    coreGroup.add(glowSphere);

    // 2c. Outer Rotating Ring 1 (Neon Crimson Torus)
    const ring1Geom = new THREE.TorusGeometry(2.1, 0.035, 16, 120);
    const ring1Mat = new THREE.MeshBasicMaterial({
      color: 0xFF1E43,
      transparent: true,
      opacity: 0.95
    });
    const ring1 = new THREE.Mesh(ring1Geom, ring1Mat);
    ring1.rotation.x = Math.PI * 0.35;
    coreGroup.add(ring1);

    // 2d. Outer Rotating Ring 2 (Neon Orange Torus, Opposing Angle)
    const ring2Geom = new THREE.TorusGeometry(1.75, 0.03, 16, 100);
    const ring2Mat = new THREE.MeshBasicMaterial({
      color: 0xFF6A00,
      transparent: true,
      opacity: 0.85
    });
    const ring2 = new THREE.Mesh(ring2Geom, ring2Mat);
    ring2.rotation.x = -Math.PI * 0.28;
    ring2.rotation.y = Math.PI * 0.2;
    coreGroup.add(ring2);

    // 2e. Outer Segmented Ring 3 (Concentric Data Ring)
    const ring3Geom = new THREE.TorusGeometry(2.45, 0.02, 12, 80);
    const ring3Mat = new THREE.MeshBasicMaterial({
      color: 0xFF8800,
      transparent: true,
      opacity: 0.6
    });
    const ring3 = new THREE.Mesh(ring3Geom, ring3Mat);
    ring3.rotation.y = Math.PI * 0.5;
    coreGroup.add(ring3);

    // 2f. Floating Geometric Fragments (Cyber Nodes)
    const nodeCount = 18;
    const nodeGeom = new THREE.BoxGeometry(0.08, 0.08, 0.08);
    const nodeMat = new THREE.MeshBasicMaterial({ color: 0xFF3355 });
    const nodesGroup = new THREE.Group();

    for (let i = 0; i < nodeCount; i++) {
      const node = new THREE.Mesh(nodeGeom, nodeMat);
      const angle = (i / nodeCount) * Math.PI * 2;
      const radius = 2.1 + (Math.sin(i * 3) * 0.2);
      node.position.set(Math.cos(angle) * radius, (Math.sin(i * 2) * 0.4), Math.sin(angle) * radius);
      nodesGroup.add(node);
    }
    coreGroup.add(nodesGroup);

    // 3. Orbiting Threat Defense Particles (Luminous Red and Orange)
    const particleCount = 450;
    const particleGeom = new THREE.BufferGeometry();
    const particlePositions = new Float32Array(particleCount * 3);
    const particleColors = new Float32Array(particleCount * 3);

    const colorRed = new THREE.Color(0xFF1E43);
    const colorOrange = new THREE.Color(0xFF6A00);
    const colorCrimson = new THREE.Color(0xDC143C);

    for (let i = 0; i < particleCount; i++) {
      // Cylindrical / spherical shell distribution around core
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos((Math.random() * 2) - 1);
      const r = 1.6 + (Math.random() * 1.8);

      const x = r * Math.sin(phi) * Math.cos(theta);
      const y = r * Math.sin(phi) * Math.sin(theta);
      const z = r * Math.cos(phi);

      particlePositions[i * 3] = x;
      particlePositions[i * 3 + 1] = y;
      particlePositions[i * 3 + 2] = z;

      // Color variation between neon red and neon orange
      const mixRatio = Math.random();
      const chosenColor = mixRatio < 0.5 ? colorRed : (mixRatio < 0.85 ? colorOrange : colorCrimson);

      particleColors[i * 3] = chosenColor.r;
      particleColors[i * 3 + 1] = chosenColor.g;
      particleColors[i * 3 + 2] = chosenColor.b;
    }

    particleGeom.setAttribute("position", new THREE.BufferAttribute(particlePositions, 3));
    particleGeom.setAttribute("color", new THREE.BufferAttribute(particleColors, 3));

    // Custom circular particle texture via canvas for silky soft glow points
    function createParticleTexture() {
      const cvs = document.createElement("canvas");
      cvs.width = 64;
      cvs.height = 64;
      const ctx = cvs.getContext("2d");
      const grad = ctx.createRadialGradient(32, 32, 0, 32, 32, 30);
      grad.addColorStop(0, "rgba(255, 255, 255, 1)");
      grad.addColorStop(0.3, "rgba(255, 50, 80, 0.85)");
      grad.addColorStop(0.7, "rgba(255, 106, 0, 0.4)");
      grad.addColorStop(1, "rgba(0, 0, 0, 0)");
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, 64, 64);
      return new THREE.CanvasTexture(cvs);
    }

    const particleMat = new THREE.PointsMaterial({
      size: 0.12,
      vertexColors: true,
      transparent: true,
      opacity: 0.9,
      map: createParticleTexture(),
      blending: THREE.AdditiveBlending,
      depthWrite: false
    });

    const particles = new THREE.Points(particleGeom, particleMat);
    scene.add(particles);

    // 4. Parallax Pointer Response
    let targetRotationX = 0;
    let targetRotationY = 0;
    let mouseX = 0;
    let mouseY = 0;

    function onPointerMove(e) {
      const clientX = e.clientX || (e.touches && e.touches[0] ? e.touches[0].clientX : 0);
      const clientY = e.clientY || (e.touches && e.touches[0] ? e.touches[0].clientY : 0);

      const halfW = window.innerWidth / 2;
      const halfH = window.innerHeight / 2;
      mouseX = (clientX - halfW) / halfW;
      mouseY = (clientY - halfH) / halfH;

      targetRotationY = mouseX * 0.55;
      targetRotationX = mouseY * 0.45;
    }

    window.addEventListener("mousemove", onPointerMove, { passive: true });
    window.addEventListener("touchmove", onPointerMove, { passive: true });

    // 5. Visibility Observer: Pause rendering when scrolled out of view
    let isVisible = true;
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        isVisible = entry.isIntersecting;
      });
    }, { threshold: 0.1 });
    observer.observe(container);

    // 6. Responsive Window Resize Handler
    function onResize() {
      if (!container) return;
      const newW = container.clientWidth || 480;
      const newH = container.clientHeight || 480;
      camera.aspect = newW / newH;
      camera.updateProjectionMatrix();
      renderer.setSize(newW, newH);
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    }
    window.addEventListener("resize", onResize);

    // 7. Animation Loop with Organic Speed & Pulsation
    let clock = new THREE.Clock();

    function animate() {
      requestAnimationFrame(animate);

      if (!isVisible) return;

      const elapsed = clock.getElapsedTime();

      // Continuous ambient rotation
      coreGroup.rotation.y += 0.009;
      coreGroup.rotation.x += 0.004;

      // Opposing rotations for rings to create gyroscopic motion
      ring1.rotation.z += 0.015;
      ring2.rotation.z -= 0.018;
      ring3.rotation.x += 0.011;

      // Inner core pulse
      const pulseScale = 1.0 + Math.sin(elapsed * 2.8) * 0.08;
      innerCore.scale.set(pulseScale, pulseScale, pulseScale);

      glowSphere.scale.set(
        1.0 + Math.sin(elapsed * 3.5) * 0.06,
        1.0 + Math.sin(elapsed * 3.5) * 0.06,
        1.0 + Math.sin(elapsed * 3.5) * 0.06
      );

      // Orbiting particles spiral rotation
      particles.rotation.y = elapsed * 0.08;
      particles.rotation.x = Math.sin(elapsed * 0.1) * 0.15;

      // Damped pointer parallax interpolation
      coreGroup.rotation.y += (targetRotationY - coreGroup.rotation.y * 0.1) * 0.04;
      coreGroup.rotation.x += (targetRotationX - coreGroup.rotation.x * 0.1) * 0.04;

      renderer.render(scene, camera);
    }

    animate();
  }

  // Initialize once DOM is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initCyberHero);
  } else {
    initCyberHero();
  }
})();
