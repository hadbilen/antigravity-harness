/**
 * silk-design — Zero-Build Vanilla Kinetic Runtime (assets/vanilla-kinetic.js)
 *
 * Provides physics-based MOTION 3 showcase primitives for Astro, static HTML,
 * Vanilla TypeScript, and single-file HTML showcase prototypes without React,
 * Framer Motion, or GSAP dependencies.
 *
 * Constitutional Invariants (antislop R-19 & DESIGN.md MODE: EDITORIAL):
 * - Automatically collapses all motion to instant state transitions (MOTION 1)
 *   when `window.matchMedia('(prefers-reduced-motion: reduce)').matches` is true.
 * - Disables magnetic cursor and border-glow tracking below 768px viewport width.
 * - Uses a single requestAnimationFrame loop for pointer-tracked border glows.
 */

const _boundElements = typeof WeakSet !== "undefined" ? new WeakSet() : null;

export function initSilkKinetic(root = typeof document !== "undefined" ? document : null) {
  if (
    typeof window === "undefined" ||
    !root ||
    typeof root.querySelectorAll !== "function" ||
    typeof window.matchMedia !== "function"
  ) {
    return () => {};
  }

  const reducedMotionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
  let isReducedMotion = reducedMotionQuery.matches;

  const cleanups = [];

  // 1. Word-stagger splitting & IntersectionObserver Entrance Choreography (-20% margin, once: true)
  const wordHeadings = Array.from(root.querySelectorAll("[data-silk-words]"));
  for (const heading of wordHeadings) {
    if (heading.dataset.silkSplitDone === "true") continue;
    const rawText = (heading.textContent || "").trim();
    if (!rawText) continue;
    heading.dataset.silkSplitDone = "true";
    heading.setAttribute("aria-label", rawText);
    heading.textContent = "";
    const words = rawText.split(/\s+/);
    words.forEach((word, index) => {
      const span = heading.ownerDocument.createElement("span");
      span.className = "silk-word";
      span.textContent = word;
      span.setAttribute("aria-hidden", "true");
      span.style.setProperty("--word-index", String(index));
      heading.appendChild(span);
      if (index < words.length - 1) {
        heading.appendChild(heading.ownerDocument.createTextNode(" "));
      }
    });
  }

  const revealTargets = Array.from(
    root.querySelectorAll("[data-silk-reveal], [data-silk-words]")
  );

  let observer = null;
  const connectRevealObserver = () => {
    if (observer) return;
    if (isReducedMotion || typeof IntersectionObserver === "undefined") {
      for (const el of revealTargets) {
        el.dataset.silkVisible = "true";
      }
      return;
    }
    observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            entry.target.dataset.silkVisible = "true";
            observer.unobserve(entry.target);
          }
        }
      },
      { rootMargin: "0px 0px -20% 0px", threshold: 0.05 }
    );
    for (const el of revealTargets) {
      if (el.dataset.silkVisible !== "true") {
        observer.observe(el);
      }
    }
  };
  connectRevealObserver();
  cleanups.push(() => {
    if (observer) {
      observer.disconnect();
      observer = null;
    }
  });

  // 2. Magnetic Buttons ([data-silk-magnetic]) — Spring-damped lean (disabled < 768px & reduced-motion)
  const magneticElements = Array.from(root.querySelectorAll("[data-silk-magnetic]"));
  for (const el of magneticElements) {
    if (_boundElements && _boundElements.has(el)) continue;
    if (_boundElements) _boundElements.add(el);
    const parsed = parseFloat(el.dataset.silkMagnetic || "");
    const strength = Number.isFinite(parsed) ? parsed : 0.15;
    const onMove = (e) => {
      if (isReducedMotion || window.innerWidth < 768) return;
      const rect = el.getBoundingClientRect();
      const cx = rect.left + rect.width / 2;
      const cy = rect.top + rect.height / 2;
      const dx = (e.clientX - cx) * strength;
      const dy = (e.clientY - cy) * strength;
      el.style.transform = `translate3d(${dx.toFixed(2)}px, ${dy.toFixed(2)}px, 0)`;
    };
    const onLeave = () => {
      el.style.transform = "translate3d(0px, 0px, 0)";
    };
    el.addEventListener("pointermove", onMove, { passive: true });
    el.addEventListener("pointerleave", onLeave, { passive: true });
    cleanups.push(() => {
      el.removeEventListener("pointermove", onMove);
      el.removeEventListener("pointerleave", onLeave);
      if (_boundElements) _boundElements.delete(el);
    });
  }

  // 3. Pointer-Tracked Conic Border Glow ([data-silk-border-glow]) — Single listener, rAF-throttled
  const glowCards = Array.from(root.querySelectorAll("[data-silk-border-glow]"));
  const hostBody =
    (root.ownerDocument && root.ownerDocument.body) ||
    (typeof document !== "undefined" ? document.body : null);
  let rafId = 0;

  const resetPointerEffects = () => {
    if (rafId) {
      window.cancelAnimationFrame(rafId);
      rafId = 0;
    }
    for (const el of magneticElements) {
      el.style.transform = "translate3d(0px, 0px, 0)";
    }
    for (const card of glowCards) {
      card.style.setProperty("--active", "0");
    }
  };

  if (glowCards.length > 0 && hostBody && (!_boundElements || !_boundElements.has(hostBody))) {
    if (_boundElements) _boundElements.add(hostBody);
    let lastX = -9999;
    let lastY = -9999;
    const proximity = 64;

    const updateGlows = () => {
      rafId = 0;
      if (isReducedMotion || window.innerWidth < 768) {
        for (const card of glowCards) {
          card.style.setProperty("--active", "0");
        }
        return;
      }
      for (const card of glowCards) {
        const rect = card.getBoundingClientRect();
        const inProximity =
          lastX >= rect.left - proximity &&
          lastX <= rect.right + proximity &&
          lastY >= rect.top - proximity &&
          lastY <= rect.bottom + proximity;
        if (!inProximity) {
          card.style.setProperty("--active", "0");
          continue;
        }
        const cx = rect.left + rect.width / 2;
        const cy = rect.top + rect.height / 2;
        const angle = (Math.atan2(lastY - cy, lastX - cx) * 180) / Math.PI + 90;
        card.style.setProperty("--active", "1");
        card.style.setProperty("--start", angle.toFixed(1));
      }
    };

    const onPointerMove = (e) => {
      if (isReducedMotion || window.innerWidth < 768) return;
      lastX = e.clientX;
      lastY = e.clientY;
      if (!rafId) {
        rafId = window.requestAnimationFrame(updateGlows);
      }
    };

    hostBody.addEventListener("pointermove", onPointerMove, { passive: true });
    cleanups.push(() => {
      hostBody.removeEventListener("pointermove", onPointerMove);
      if (rafId) {
        window.cancelAnimationFrame(rafId);
        rafId = 0;
      }
      if (_boundElements) _boundElements.delete(hostBody);
    });
  }

  // 4. Viewport Resize & Live Reduced-Motion Synchronization
  const onResize = () => {
    if (window.innerWidth < 768) {
      resetPointerEffects();
    }
  };
  window.addEventListener("resize", onResize, { passive: true });
  cleanups.push(() => window.removeEventListener("resize", onResize));

  const onMotionChange = (e) => {
    isReducedMotion = e.matches;
    if (isReducedMotion) {
      for (const el of revealTargets) {
        el.dataset.silkVisible = "true";
      }
      resetPointerEffects();
    } else {
      connectRevealObserver();
    }
  };
  reducedMotionQuery.addEventListener("change", onMotionChange);
  cleanups.push(() => reducedMotionQuery.removeEventListener("change", onMotionChange));

  return () => {
    for (const fn of cleanups) fn();
  };
}

export function runSilkViewTransition(mutateDomCallback) {
  if (typeof mutateDomCallback !== "function") return;
  if (
    typeof document === "undefined" ||
    typeof window === "undefined" ||
    typeof document.startViewTransition !== "function" ||
    typeof window.matchMedia !== "function" ||
    window.matchMedia("(prefers-reduced-motion: reduce)").matches
  ) {
    mutateDomCallback();
    return;
  }
  document.startViewTransition(() => {
    mutateDomCallback();
  });
}
