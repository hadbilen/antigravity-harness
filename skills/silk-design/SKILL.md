---
name: silk-design
description: "Kinetic motion, smooth-scrolling, fluid typography, and design-token capability toolbox for high-end landing pages, marketing sites, and portfolios. Enforces purposeful physics-based motion (Lenis, GSAP, Framer Motion, Tailwind v4) while strictly conforming to antislop and MOTION 3 dials. Invoke with /silk-design when explicitly building or restyling showcase/marketing pages, heroes, interactive landing pages, or when MOTION 3 is declared. DO NOT use on standard engineering dashboards or MOTION 1/2 baselines."
---

# silk-design — Kinetic Interface and Motion Engineering Toolkit

This skill equips web interfaces with buttery smooth, physics-based motion, fluid typography, and centrally orchestrated design tokens modeled after modern showcase experiences.

---

## 1. Architectural Hierarchy and Constitutional Bridge

This skill is **not an independent design system or style arbiter**. It operates strictly within the three-tier design hierarchy:

1. **`DESIGN.md` (Identity & Soul):** Dictates project identity, color tokens, typography, and dials.
2. **`antislop` (Filter & Delivery Gate):** Prevents gratuitous trend accumulation, fake content, accessibility violations, and visual bloat.
3. **`silk-design` (Kinetic Armory):** Implements the antislop tenet: *"Removing slop does not make a design great; vitality must be added purposefully"* via verified physics and animation formulas.

### Invocation and Scope Rules

* **Allowed Scenarios:**
  * The user explicitly requests a showcase, landing page, marketing site, portfolio, or creative experience (`/silk-design`, `silk-design`, `motion 3`, "fluid kinetic motion").
  * The project's local `DESIGN.md` declares the motion dial as **`MOTION 3`**.
* **STRICTLY Prohibited Scenarios:**
  * Standard engineering dashboards, administrative consoles, CRUD interfaces, and data tables.
  * Projects declaring **`MOTION 1`** (`0ms` / static, instantaneous state changes) or **`MOTION 2`** (`150ms–200ms` functional micro-interactions; Lenis and scroll animations are barred).

---

## 2. Antislop Safety Boundaries (Mandatory Invariants)

Every technique in `silk-design` must pass the `antislop` delivery gate:

1. **Accessibility and Motion Preference (`prefers-reduced-motion` - R-19):**
   * Always emit client-side `@media (prefers-reduced-motion: reduce)` CSS rules and `window.matchMedia('(prefers-reduced-motion: reduce)')` JavaScript guards so if the host system enables "reduce motion", Lenis smooth-scrolling, parallax, and GSAP ScrollTrigger are disabled entirely or collapsed to instant zero-duration transitions (`duration: 0`, `MOTION 1`).
2. **Glassmorphism Discipline (R-10):**
   * Do not apply `.card { backdrop-filter: blur(8px); }` indiscriminately across cards. Reserve blur solely for sticky navigation bars, modals, or drawers where visible underlay content provides spatial depth.
3. **Contrast and Glow Limits (R-13, R-25):**
   * Glow effects (`BorderGlow`, `neon`) must never compromise text legibility. All typography must maintain at least **WCAG AA 4.5:1** contrast against backgrounds.
4. **Honest Content (R-17, R-18, R-38):**
   * Reference compositions (`references/templates.md`) are wireframe skeletons only. Do not copy fake testimonial quotes, fabricated logos, or artificial counters into production. If real data is unavailable, omit those sections.

---

## 3. Non-Negotiable Engineering Foundation

The baseline skeleton for kinetic showcase experiences:

### 1. Root-Level Lenis Smooth Scrolling
Wrap the application root once; **never** use CSS `scroll-behavior: smooth`:
```tsx
import { ReactLenis } from 'lenis/react'
<ReactLenis root>{app}</ReactLenis>
```
Trigger in-page anchor navigation via `useLenis().scrollTo(el)` (see `assets/useButtonClick.ts`).

### 2. Overscroll Bounce Prevention and Thin Scrollbar
Global CSS rules in `assets/foundation.css`:
```css
html, body { overscroll-behavior: none; }
* { scrollbar-width: thin; scrollbar-color: rgb(0 0 0 / 0.3) transparent; }
```

### 3. Token Architecture and Single Radius Knob (`--radius`)
Nine CSS variables and a single `--radius` knob govern site-wide color and corner radiuses (Tailwind v4 `@theme inline`). The hex values below are illustrative `MOTION 3` showcase defaults; always defer to the active project's `DESIGN.md` tokens (e.g., `#09090B` / `#18181B`) unless an explicit showcase palette override is declared:
```css
:root {
  --background: #0a0a0a;
  --card: #1a1a1a;
  --foreground: #eeeded;
  --primary-cta: #00FFAB;
  --primary-cta-text: #000000;
  --secondary-cta: #1a1a1a;
  --secondary-cta-text: #ffffffe6;
  --accent: #8a8a8a;
  --background-accent: #00d5c7;
  --radius: 0.75rem; /* Single knob: lg, md, sm derive from here */
}

@theme inline {
  --color-background: var(--background);
  --color-card: var(--card);
  --color-foreground: var(--foreground);
  --color-primary-cta: var(--primary-cta);
  --color-primary-cta-text: var(--primary-cta-text);
  --color-secondary-cta: var(--secondary-cta);
  --color-secondary-cta-text: var(--secondary-cta-text);
  --color-accent: var(--accent);
  --color-background-accent: var(--background-accent);
  --radius-lg: var(--radius);
  --radius-md: calc(var(--radius) - 2px);
  --radius-sm: calc(var(--radius) - 4px);
}
```

### 4. Fluid Typography
Replace rigid pixel breakpoints with `clamp(min, vw + rem, max)` scalers (minimum `0.75rem` / `12px` floor per `antislop` R-06). Text scales smoothly with viewport width and browser zoom without causing mobile horizontal overflow:
```css
--text-lg:  clamp(1rem, 1vw + 0.65rem, 1.125rem);
--text-4xl: clamp(1.5rem, 2vw + 0.9rem, 2.25rem);
--text-6xl: clamp(2.25rem, 3.3vw + 1.1rem, 3.3rem);
--text-9xl: clamp(3.25rem, 7vw + 1.5rem, 7rem);
```

### 5. Standard Entrance Reveal Choreography
Uniform reveal rhythm across blocks (React `motion/react` or zero-build `assets/vanilla-kinetic.js` `[data-silk-reveal]` / `[data-silk-words]`):
```tsx
initial="hidden" whileInView="visible"
viewport={{ once: true, margin: "-20%" }}
transition={{ duration: 0.6, ease: "easeOut" }} // Text staggerChildren: 0.04
```
Available components: `assets/ScrollReveal.tsx` (blocks), `assets/TextAnimation.tsx` (word-by-word titles), and `assets/vanilla-kinetic.js` (`initSilkKinetic()` for zero-build HTML/Astro/Vanilla JS).

---

## 4. Toolkit and Asset Directory

Consult the reference library when needed:
* **Entrances & Text Effects:** Word-by-word animated headers, blur-to-sharp transitions. → `references/effects.md`, `assets/{TextAnimation,ScrollReveal}.tsx`, `assets/vanilla-kinetic.js`
* **Scroll-Driven Effects:** Parallax (`useScroll`/`useTransform` or native CSS `animation-timeline: view()`), scrubbed video, pinned sections, revealed footers. → `references/effects.md`, `assets/{HeroVideoScroll,AboutTextFill,FooterBrandReveal}.tsx`
* **Cursor & Pointer Interactions:** Magnetic buttons (spring `150/15` or `[data-silk-magnetic]`), pointer-following border glows (`[data-silk-border-glow]`), draggable tags. → `references/effects.md`, `assets/{ButtonMagnetic,BorderGlow,HoverPattern}.tsx`, `assets/vanilla-kinetic.js`
* **Marquees:** Infinite CSS marquee with edge gradient masks. → `references/effects.md`, `assets/{animations,masks}.css`
* **Page Transitions:** Fullscreen curtain overlay, DrawSVG spiral transitions, or native `View Transitions API` (`runSilkViewTransition`). → `references/effects.md`, `assets/{NavbarFullscreen,PageTransitionSwirl}.tsx`, `assets/vanilla-kinetic.js`
* **10 Style Skins:** Ten pre-built styling palettes in `references/design-system.md` (minimal, elegant, soft, bold, glass, neon, gradient, metallic, shadow, elevated). Switch skins by swapping `.card` and `.primary-button` CSS definitions (subject to Section 2: `glass` blur is restricted to sticky navbars/modals/drawers per R-10, and `neon` glow is restricted to a single primary focal CTA per R-13).
* **23 Reference Compositions:** Production-ready color palettes, font pairings, and section rhythms in `references/templates.md`.

---

## 5. Technology Stack (Dual-Track Runtime)

 Domain scope remains strictly locked to **`MODE: EDITORIAL` (`MOTION 3`)** showcase, landing, portfolio, and interactive narrative pages (`MODE: UTILITY` dashboards and CRUD tables remain prohibited). Within that editorial scope, two first-class runtime tracks are supported:

1. **Track A — Component Framework Stack (React / Next.js):**
   * **Core:** React + Vite (or Next.js) + Tailwind v4 + `assets/*.tsx`
   * **Kinetic Libraries:** `motion` (`motion/react`), `gsap` + `@gsap/react` (ScrollTrigger, Draggable, DrawSVGPlugin), and `lenis` (`lenis/react`).
2. **Track B — Zero-Build Vanilla HTML/CSS/JS, Astro & Static Runtime:**
   * **Core:** `assets/foundation.css` + `assets/animations.css` + `assets/masks.css` + `assets/vanilla-kinetic.js` (`initSilkKinetic()` and `runSilkViewTransition()`).
   * **Native Browser Primitives:** CSS `clamp()` fluid typography, `IntersectionObserver` (`-20%` root margin, `once: true`) word/block reveals, CSS Scroll-Driven Animations (`animation-timeline: view()`), `document.startViewTransition` curtain wipes, and rAF-throttled `[data-silk-magnetic]` / `[data-silk-border-glow]` pointer physics — all automatically guarded by `@media (prefers-reduced-motion: reduce)` and `window.matchMedia('(prefers-reduced-motion: reduce)')` (`antislop` R-19).

