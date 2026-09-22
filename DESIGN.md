# Global Baseline Design Contract

This document serves as the default visual and interaction design contract for all projects that do not declare a local `DESIGN.md`.
If a project contains a local `DESIGN.md` in its root directory, that local file strictly takes precedence.
All user interface outputs are subject to the `antislop` quality filter and delivery gates.

Dial: ENERGY 2 / RHYTHM 2 / MOTION 2
(If the host operating system has `prefers-reduced-motion` enabled, motion automatically falls back to MOTION 1.)

---

## 1. Context and Design Philosophy

- **Goal:** Robust, high-contrast, purposeful engineering interfaces built for clarity and speed.
- **What We Are Explicitly NOT:** A generic AI SaaS dashboard (no purple/pink gradients, no indiscriminate glassmorphism, no purposeless 3D illustrations, no decorative glitter).
- **Craftsmanship Standards:**
  1. *Purpose Test:* Every visual technique (shadow, icon, border, color) must have a single-sentence functional justification. "It looks nice" is never an acceptable justification.
  2. *Honest Content:* No fake metrics, fabricated testimonial quotes, or meaningless placeholder copy.

---

## 2. Dials

- **ENERGY 2:** Neutral surfaces, high-contrast typography, and a single non-distracting accent color instead of oversaturated glows or vibrant backdrops.
- **RHYTHM 2:** Strict 4px/8px spatial rhythm. Predictable, structured layouts that preserve information density and hierarchy.
- **MOTION 2:** Functional micro-transitions only (150ms–200ms easing for `:hover`, `:focus-visible`, and `:active`). Infinite looping animations, floating cards, and scroll-triggered entrance choreographies are prohibited.

---

## 3. Color and Contrast Contract

Direction: Modern Zinc/Slate neutral surfaces with a focused Cobalt Blue accent.

### Rules
- All text must meet at least **4.5:1** contrast against its background (WCAG AA). Large text (WCAG: at least 24px / 18pt regular, or 18.67px / 14pt bold) must meet at least **3:1**.
- Form input borders, icons, and status indicators must meet at least **3:1**.
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
| Dark · Primary text on card | `#F4F4F5` | `#18181B` | 16.12:1 | 4.5:1 |
| Dark · Secondary text on card | `#A1A1AA` | `#18181B` | 6.91:1 | 4.5:1 |
| Dark · Accent text on card | `#60A5FA` | `#18181B` | 6.97:1 | 4.5:1 |
| Dark · Input border on card | `#71717A` | `#18181B` | 3.67:1 | 3:1 |
| Dark · Primary button text | `#FFFFFF` | `#2563EB` | 5.17:1 | 4.5:1 |
| Dark · Alternate button text | `#09090B` | `#3B82F6` | 5.41:1 | 4.5:1 |
| Dark · Disabled control text | `#A1A1AA` | `#27272A` | 5.81:1 | 3:1 |

### Status Colors (Semantic)
- **Success:** Green (`#16A34A` light / `#22C55E` dark)
- **Error / Danger:** Red (`#DC2626` light / `#EF4444` dark)
- **Warning:** Amber (`#D97706` light / `#F59E0B` dark)
- **Info:** Blue (`#2563EB` light / `#3B82F6` dark)
- *Note: Status cannot rely solely on color; an accompanying label or accessible icon (`aria-label`) is required.*

---

## 4. Typography and Numbers

- **UI Font Stack:** System font stack (`system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif`). Do not import heavy external web fonts; native performance and optical clarity are paramount.
- **Monospace Font:** Reserved strictly for code snippets, CLI output, hashes, API keys, and UUIDs. Never use monospace as decorative styling for headings.
- **Tabular Figures (`tabular-nums`):** Financial data, counters, timestamps, and data tables must enforce `font-variant-numeric: tabular-nums` (or Tailwind `tabular-nums`) to prevent layout jitter.
- **Size Standards:**
  - Minimum caption text: 12px.
  - Standard body text: 14px / 16px.
  - Mobile form controls (input, select): Minimum 16px to prevent iOS auto-zoom on focus.
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
   - Controls must drop back to neutral surface tones (`#27272A` dark / `#E2E8F0` light) with muted text (`#71717A` / `#A1A1AA` dark / `#94A3B8` light).
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
2. `Dial: ENERGY [1-5] / RHYTHM [1-5] / MOTION [1-5]`
3. `## 1. Context (Audience, Environment, Purpose)`
4. `## 2. Personality & "What We Are Not"`
5. `## 3. Color Palette & Measured Contrast Ratios`
6. `## 4. Typography & Touch Targets`
7. `## 5. Project-Specific Workflows & States`
