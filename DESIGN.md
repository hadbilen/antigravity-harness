# Global Baseline Design Contract

This document serves as the default visual and interaction design contract for all projects that do not declare a local `DESIGN.md`.
If a project contains a local `DESIGN.md` in its root directory, that local file strictly takes precedence.
All user interface outputs are subject to the `antislop` quality filter and delivery gates.

Dial: ENERGY 2 / RHYTHM 2 / MOTION 2
(Enforce `prefers-reduced-motion` fallback to `MOTION 1` by emitting client-side CSS `@media (prefers-reduced-motion: reduce)` rules and JavaScript `window.matchMedia('(prefers-reduced-motion: reduce)')` guards in generated code; agents cannot directly observe the host OS motion setting.)

---

## 1. Context and Design Philosophy

- **Goal:** Robust, high-contrast, purposeful engineering interfaces built for clarity and speed.
- **What We Are Explicitly NOT:** A generic AI SaaS dashboard (no purple/pink gradients, no indiscriminate glassmorphism, no purposeless 3D illustrations, no decorative glitter).
- **Craftsmanship Standards:**
  1. *Purpose Test:* Every visual technique (shadow, icon, border, color) must have a single-sentence functional justification. "It looks nice" is never an acceptable justification.
  2. *Honest Content:* No fake metrics, fabricated testimonial quotes, or meaningless placeholder copy.

---

## 2. Dials & Domain Archetype Modes

- **ENERGY 2 (Default Utility Baseline):** Neutral surfaces, high-contrast typography, and a single non-distracting accent color instead of oversaturated glows or vibrant backdrops.
- **RHYTHM 2 (Default Utility Baseline):** Strict 4px/8px spatial rhythm. Predictable, structured layouts that preserve information density and hierarchy.
- **MOTION 2 (Default Utility Baseline):** Functional micro-transitions only (150ms–200ms easing for `:hover`, `:focus-visible`, and `:active`). Infinite looping animations, floating cards, and scroll-triggered entrance choreographies are prohibited in `MODE: UTILITY`.

### 2.1 Domain Archetype Modes (Automatic Task-Shape Routing)

To prevent every non-dashboard interface from collapsing into a sterile dark-zinc admin box, select the archetype mode that matches the task's domain when no local `DESIGN.md` overrides it:

1. **`MODE: UTILITY` (Default — Engineering Dashboards, Admin Consoles, Data Tables, Developer Tools):**
   - **Dials:** `ENERGY 2 / RHYTHM 2 / MOTION 2`.
   - **Surface & Type:** Zinc/Slate neutral surfaces (`#09090B` / `#18181B` dark, `#FFFFFF` / `#F8FAFC` light) with Cobalt Blue (`#2563EB`) accent, `system-ui` font stack, `tabular-nums` on all numeric columns, and all five data lifecycle states (Section 6.1).
2. **`MODE: EDITORIAL` (Product Showcases, Marketing Pages, Portfolios, Interactive Narratives — pairs with `silk-design`):**
   - **Dials:** `ENERGY 4 / RHYTHM 4 / MOTION 3`.
   - **Composition & Anti-Boxification:** At most one primary bordered card group per viewport; delineate secondary sections with spatial whitespace (`24px–64px`), typography, or single-edge hairlines (`border-t` / `border-b`) rather than nested bordered boxes. Never place 3+ identical-width sibling cards in a row; use an asymmetric focal split (`55%–65%` dominant element paired with `35%–45%` compact list/rows).
   - **Typography & Scale:** Expressive display + body font pairing (pinned/self-hosted web fonts permitted with `font-display: swap`), fluid viewport scaling (`clamp()`), and a minimum **`3.5:1` size ratio** between the primary display heading and body copy.
3. **`MODE: GAME & INTERACTIVE` (Two-Dimensional and Three-Dimensional Games, Simulations, Interactive Canvases):**
   - **Dials:** `ENERGY 4–5 / RHYTHM 4 / MOTION 4–5` (governed alongside `skills/game-engineering/SKILL.md`).
   - **Canvas vs. Chrome Separation:** Inside the interactive canvas (`<canvas>`, Web Graphics Library (`WebGL`), shader viewports, or game engine scenes) and diegetic Head-Up Display (`HUD`) overlays, continuous frame-loop animations (`requestAnimationFrame`, idle character breathing, particle emitters, camera trauma/screen shake, hit-stop, and directional status glows) are explicitly authorized and exempt from `MOTION 2` static restrictions. Always provide an accessible setting or `prefers-reduced-motion` guard that attenuates screen shake and rapid flashing.
   - **Expanded Semantic & Rarity Palette:** Beyond the single-accent rule of `MODE: UTILITY`, game interfaces may define distinct chromatic tokens for vitality/health, mana/energy, stamina, elemental affinities, and item rarity tiers (Common, Uncommon, Rare, Epic, Legendary), plus translucent diegetic HUD backing plates (`--surface-hud-scrim: rgba(10, 14, 23, 0.78)`), provided every text label maintains at least **4.5:1** contrast (or **3:1** for large display text) against its immediate scrim or panel backing. Raw uncalibrated programmer-art primaries (`#FF0000`, `#00FF00`, `#0000FF`, `#FFFF00`, `#FF00FF`, `#00FFFF`) are forbidden.
   - **Atmospheric Typography & Input Feedback Triad:** Pinned or bundled thematic display, pixel, serif, or geometric fonts are required for game titles, combat callouts, and diegetic HUD panels (`system-ui` is prohibited on game title screens and diegetic banners; in offline `file://` single-file HTML games per `skills/vibecoder/SKILL.md`, use an inline `data:font/woff2;base64` subset `<= 32 KB`, procedural `<canvas>`/`<svg>` display glyphs, or named local non-`system-ui` stacks such as `'Trebuchet MS', Georgia, serif`). Every primary player action must trigger at least two synchronous channels of the **Input Feedback Triad**: (1) visual (`80ms–140ms` transform/squash-stretch tween, 2–4 frame hit-flash, directional knockback, or pooled particle burst), (2) spatial/camera (decaying trauma-based screen shake honoring `prefers-reduced-motion` or 2–4 frame hit-stop), and (3) audio/tactile cue (synthesized WebAudio procedural sound effect or audio/haptic hook with mute toggle); unstyled browser default `<button>` or `<input>` controls inside a game viewport are forbidden.

---

## 3. Color and Contrast Contract

Direction: Modern Zinc/Slate neutral surfaces with a focused Cobalt Blue accent.

### Rules
- All text must meet at least **4.5:1** contrast against its background (WCAG AA). Large text (WCAG: at least `1.5rem` / `18pt` (`24px` equivalent) regular, or `1.167rem` / `14pt` (`18.67px` equivalent) bold) must meet at least **3:1**.
- Form input borders, icons, and status indicators must meet at least **3:1**; live or active status indicator dots use a solid `0.375rem–0.5rem` (`6px–8px`) circle (where a subtle static semantic glow is permitted solely on genuine active/live status indicator dots per `skills/antislop/SKILL.md` `R-13`, never endless pulsing or decorative non-state dots).
- Never hardcode arbitrary hex color codes; use CSS variables or semantic design tokens.
- Gradients are permitted exclusively for state transitions or data visualization; full-page background gradients and decorative radial glows are banned.
- Shadows are reserved strictly for elevation hierarchy (dropdowns, modals, popovers, sticky headers); flat cards are delineated by background tone and subtle borders.

### Light Theme

| Role | Value | Usage |
|---|---|---|
| Background Canvas | `#FFFFFF` | Main canvas |
| Card / Surface | `#F8FAFC` | Subtle border: `#E2E8F0` |
| Secondary Surface | `#F1F5F9` | Section divider or neutral panel |
| Divider Line | `#E2E8F0` | Structural separator (decorative, not a control boundary) |
| Input Border | `#64748B` | Form control boundary on card surface |
| Primary Text | `#0F172A` | Body and headings |
| Secondary / Placeholder | `#475569` | Supporting text, placeholders |
| Accent Text | `#1D4ED8` | Links and emphasis |
| Primary Button | Background `#2563EB`, Text `#FFFFFF` | Primary action |
| Disabled Control | Background `#E2E8F0`, Text `#64748B` | Neutral disabled surface |

### Dark Theme

| Role | Value | Usage |
|---|---|---|
| Background Canvas | `#09090B` | Main canvas (deep zinc rather than pitch black) |
| Card / Surface | `#18181B` | Subtle border: `#27272A` |
| Secondary Surface | `#27272A` | Section divider or neutral panel |
| Divider Line | `#27272A` | Structural separator (decorative, not a control boundary) |
| Input Border | `#71717A` | Form control boundary on card surface |
| Primary Text | `#F4F4F5` | Body and headings |
| Secondary / Placeholder | `#A1A1AA` | Supporting text, placeholders |
| Accent Text | `#60A5FA` | Links and emphasis |
| Primary Button | Background `#2563EB`, Text `#FFFFFF` (or Bg `#3B82F6`, Text `#09090B`) | Primary action |
| Disabled Control | Background `#27272A`, Text `#A1A1AA` | Neutral disabled surface |
| Diegetic HUD Scrim | `--surface-hud-scrim: rgba(10, 14, 23, 0.78)` | Translucent HUD backing plate (`MODE: GAME & INTERACTIVE`) |

### Measured Contrast Pairs

Computed with the WCAG 2.x relative-luminance formula (`skills/antislop-human/contrast-check.py`).
The harness self-audit (`scripts/meta_audit.py`, Pass 6) recomputes every row; a stated ratio that
differs from the measurement, or a pair below its minimum, fails the audit.

| Pair | Foreground | Background | Ratio | Minimum |
|---|---|---|---|---|
| Light · Primary text on canvas | `#0F172A` | `#FFFFFF` | 17.85:1 | 4.5:1 |
| Light · Secondary text on canvas | `#475569` | `#FFFFFF` | 7.58:1 | 4.5:1 |
| Light · Secondary text on card | `#475569` | `#F8FAFC` | 7.24:1 | 4.5:1 |
| Light · Accent text on canvas | `#1D4ED8` | `#FFFFFF` | 6.70:1 | 4.5:1 |
| Light · Input border on card | `#64748B` | `#F8FAFC` | 4.55:1 | 3:1 |
| Light · Primary button text | `#FFFFFF` | `#2563EB` | 5.17:1 | 4.5:1 |
| Light · Disabled control text | `#64748B` | `#E2E8F0` | 3.86:1 | 3:1 |
| Light · Success status text on secondary surface | `#15803D` | `#F1F5F9` | 4.58:1 | 4.5:1 |
| Light · Warning status text on secondary surface | `#B45309` | `#F1F5F9` | 4.58:1 | 4.5:1 |
| Dark · Primary text on card | `#F4F4F5` | `#18181B` | 16.12:1 | 4.5:1 |
| Dark · Secondary text on card | `#A1A1AA` | `#18181B` | 6.91:1 | 4.5:1 |
| Dark · Accent text on card | `#60A5FA` | `#18181B` | 6.97:1 | 4.5:1 |
| Dark · Input border on card | `#71717A` | `#18181B` | 3.67:1 | 3:1 |
| Dark · Primary button text | `#FFFFFF` | `#2563EB` | 5.17:1 | 4.5:1 |
| Dark · Alternate button text | `#09090B` | `#3B82F6` | 5.41:1 | 4.5:1 |
| Dark · Disabled control text | `#A1A1AA` | `#27272A` | 5.81:1 | 3:1 |

### Status Colors (Semantic)
- **Success:** Green (`#15803D` light text & secondary-surface indicator; `#16A34A` non-text indicator on `#FFFFFF`/`#F8FAFC` only / `#22C55E` dark)
- **Error / Danger:** Red (`#DC2626` light text on `#FFFFFF`/`#F8FAFC` and indicator on `#F1F5F9`; `#B91C1C` text on `#F1F5F9` / `#EF4444` dark on `#18181B`; `#F87171` text on `#27272A`)
- **Warning:** Amber (`#B45309` light text & secondary-surface indicator; `#D97706` non-text indicator on `#FFFFFF`/`#F8FAFC` only — never on `#F1F5F9` where it drops to `2.91:1` / `#F59E0B` dark)
- **Info:** Blue (`#1D4ED8` light text, `#2563EB` light indicator & canvas/card text / `#60A5FA` dark text, `#3B82F6` dark indicator & card text)
- *Note: Status cannot rely solely on color; an accompanying label or accessible icon (`aria-label`) is required.*

---

## 4. Typography and Numbers

- **Font Family Budget:** At most **2 font families** per view (UI + Monospace in `MODE: UTILITY`, or Display + Body in `MODE: EDITORIAL` and `MODE: GAME & INTERACTIVE`).
- **UI Font Stack:** System font stack (`system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif`). Do not import heavy external web fonts; native performance and optical clarity are paramount.
- **Monospace Font:** Reserved strictly for code snippets, CLI output, hashes, API keys, and UUIDs. Never use monospace as decorative styling for headings.
- **Tabular Figures (`tabular-nums`):** Financial data, counters, timestamps, and data tables must enforce `font-variant-numeric: tabular-nums` (or Tailwind `tabular-nums`) to prevent layout jitter.
- **Size Standards (`rem` / Fluid Units):**
  - Declare font sizes in relative units (`rem` or `clamp()`) rather than fixed `px` rules so text scales cleanly to `200%` zoom (`skills/antislop-human/SKILL.md`).
  - Minimum caption text: `0.75rem` (`12px` equivalent at `16px` root).
  - Standard body text: `0.875rem` / `1rem` (`14px` / `16px` equivalent at `16px` root).
  - Mobile form controls (`input`, `select`): Minimum `1rem` (`16px` equivalent at `16px` root) to prevent iOS auto-zoom on focus while scaling with browser text zoom.
  - Decorative pseudo-labels (`uppercase tracking-widest`) are prohibited.

---

## 5. Touch, Spacing, and Ergonomics

- **Touch Targets:** On touch screens, all buttons and interactive elements must measure at least **44×44px** (primary actions **48×48px**).
- **Zero Mobile Horizontal Overflow:** At 320px and 375px viewport widths, horizontal scrolling (`overflow-x`) is forbidden; content must reflow cleanly or live inside explicit scroll containers.
- **Spacing Rhythm:** Adhere strictly to 4px/8px multiples (4, 8, 12, 16, 24, 32, 48px) rather than arbitrary pixel offsets.
- **Keyboard Accessibility:**
  - Every interactive element must be reachable in logical order via `Tab`.
  - Never remove focus rings without replacement (`outline: none` alone is banned; always provide visible `:focus-visible` styling).
  - Modal dialogs must trap focus, dismiss on `Escape`, and return focus to the triggering element upon close.

---

## 6. The Five Mandatory Component States & Interactive Control States

### 6.1 Data Lifecycle States
Every component handling dynamic data must account for five states:
1. **Default:** Normal operational state with complete, valid data.
2. **Loading:** Structured skeleton loader or clear indicator preventing layout shifts while data loads.
3. **Empty:** Honest guidance explaining what to do when no data exists (no dead blank space).
4. **Error:** Clear description of why the failure occurred, paired with an actionable "Retry" button.
5. **Success:** Immediate, transient feedback following create, update, or delete operations.

### 6.2 Interactive Control States (Buttons, Inputs, Toggles)
All interactive controls must implement explicit states:
1. **Default:** Standard surface or accent styling.
2. **Hover:** Predictable micro-transition (150ms) with subtle brightness change.
3. **Active / Pressed:** Visual depression or darker tone indicating actuation.
4. **Focus-Visible:** Unambiguous 2px focus ring (`#3B82F6` or `#60A5FA`) with clear offset; removing focus rings without replacement is strictly prohibited.
5. **Disabled:**
   - **Prohibition:** Disabled controls must NEVER retain saturated or bright accent backgrounds (e.g. `#3B82F6` or `#2563EB`). Maintaining an active accent background with dimmed text is strictly classified as unreadable UI slop (contrast failure).
   - Controls must drop back to neutral surface tones (`#27272A` dark / `#E2E8F0` light) with muted text (`#A1A1AA` dark, `5.81:1` on `#27272A` / `#64748B` light, `3.86:1` on `#E2E8F0`).
   - Text within disabled controls must maintain readable contrast (at least 3:1 for disabled states, 4.5:1 preferred) against the neutral disabled surface without blending into unreadable mud.

---

## 7. Tone and Copywriting (Anti-Slop Copywriting)

- Banned AI hype buzzwords: *"Streamline", "supercharge", "unleash", "revolutionary", "seamless", "next-gen"*.
- State actions plainly with direct verbs: *"Download Project", "Generate Invoice", "Rotate Secret"*.
- Prohibit fabricated social proof: No unverified company logos, fake testimonial quotes, or fabricated counter statistics ("10,000+ happy developers").

---

## 8. Local Project Overrides

When a specific project requires custom brand styling, alternative color tokens, or different dials, place a `DESIGN.md` in the project root:
1. `# <Project Name> Design Contract`
2. `Mode: UTILITY | EDITORIAL | GAME & INTERACTIVE`
3. `Dial: ENERGY [1-5] / RHYTHM [1-5] / MOTION [1-5]`
4. `## 1. Context (Audience, Environment, Purpose)`
5. `## 2. Personality & "What We Are Not"`
6. `## 3. Color Palette & Measured Contrast Ratios`
7. `## 4. Typography & Touch Targets`
8. `## 5. Project-Specific Workflows, Canvas/HUD Rules & States`

