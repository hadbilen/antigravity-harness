# Design system — tokens, type, radius, fonts, the 10 style skins

The whole runtime design system is **one CSS file** (`assets/foundation.css`, ~190 lines). Copy it,
change the 9 colors + `--radius` + font, and you have a themed, smooth site. This is the entire trick.

## 1. Token architecture (9 custom properties → Tailwind)

Define raw values on `:root`, then re-export them to Tailwind v4 via `@theme inline`. That gives you
`bg-background`, `text-foreground`, `bg-primary-cta`, `border-accent`, etc. as normal utilities that
recolor the whole site when you change one line.

```css
:root {
  --background: #0a0a0a;        /* page bg            */
  --card: #1a1a1a;              /* surface bg         */
  --foreground: #eeeded;        /* text               */
  --primary-cta: #00FFAB;       /* primary button bg  */
  --primary-cta-text: #000000;  /* primary label      */
  --secondary-cta: #1a1a1a;
  --secondary-cta-text: #ffffffe6;
  --accent: #737373;            /* borders / glows    */
  --background-accent: #00d5c7; /* decorative wash    */
  --radius: 2rem;               /* ONE knob, see §2   */
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
  /* fonts */
  --font-sans: "Inter", sans-serif;
  --font-tight: "Inter Tight", sans-serif;
}
```

That's it — **no scales, no numeric color steps.** Nine roles. To re-theme a whole site you change
these nine values. (This is why the 22 source sites are "different" — they only swap these + a font.)
Everything auto-recolors because the component styles below are built from `color-mix(... var(--color-*) ...)`.

## 2. The radius scale — one knob

`--radius` drives everything. Set it once; the scale derives:
```css
@theme inline {
  --radius-lg: var(--radius);
  --radius-md: calc(var(--radius) - 2px);
  --radius-sm: calc(var(--radius) - 4px);
}
```
Common values: `0.5rem` (rounded), `0.75rem` (smooth), `1.5rem`/`2rem` (soft/pill). Use `rounded`
(→ `--radius-sm`) on small controls, `rounded-lg` on cards.

## 3. Fluid typography — the smoothness multiplier

**Every** size is a `clamp(min, vw, max)`, never a fixed px. Text grows with the viewport, so it never
looks cramped on mobile or tiny on 4K. Verbatim scale (from `assets/foundation.css`):

```css
--text-lg:  clamp(0.75rem, 1vw, 1rem);
--text-xl:  clamp(0.825rem, 1.1vw, 1.1rem);
--text-4xl: clamp(1.5rem, 2vw, 2rem);
--text-6xl: clamp(2.475rem, 3.3vw, 3.3rem);
--text-7xl: clamp(3rem, 4vw, 4rem);
--text-9xl: clamp(5.25rem, 7vw, 7rem);
/* …full 14-step scale --text-2xs … --text-9xl in foundation.css */
```
Under `@media (max-width: 768px)` they're overridden to pure-vw values (`--text-6xl: 8.5vw`, etc.) so
headings stay punchy on phones. **Content width** is also a clamp:
`--width-content-width: clamp(40rem, 72.5vw, 100rem)` (→ `87.5vw` under 1440px, `80vw` on mobile) —
used as `w-content-width` / `mx-auto` on every section's inner wrapper.

## 4. Fonts

17 families in play; body is almost always **Inter**. Load via a `<link>` in `index.html` (Google Fonts)
and set `--font-sans`. Heading-font pairings the system ships (heading → body):
Inter Tight → Inter · DM Sans → Inter · Manrope → DM Sans · Poppins → Inter · Montserrat → Inter ·
Archivo → Inter · Plus Jakarta Sans → Inter · Figtree → Inter · **Playfair Display → Inter** (the one
serif option, for elegant/editorial). Neutral geometric heading + Inter body is the safe default.

**The accent-font slot.** The kit reserves a third slot — `--font-serif` — for one expressive display
face (Playfair, a handwritten face, a custom display font), used *sparingly*: the italic highlight
word inside a sans headline (`<span className="font-serif italic">{highlight}</span>`), a section
title, a handwritten annotation. One accent word in a 9xl headline changes the whole personality for
free; don't set body text in it.

**Full-width wordmarks.** For brand heroes/footers where the name must span the container exactly at
any width, don't guess a size — measure: canvas `ctx.measureText` at 100px, then
`fontSize = containerWidth / textWidth * 100`, re-run in a ResizeObserver, and drop `line-height` to
`0.8` when the text has no descenders (`/[gjpqy]/`). Verbatim: `assets/AutoFillText.tsx`.

## 5. The three component classes (verbatim default = "glass")

`assets/foundation.css` bakes in three reusable classes. This default is the **glass** skin:

```css
.card {                              /* glass-elevated */
  backdrop-filter: blur(8px);
  background: linear-gradient(to bottom right,
    color-mix(in srgb, var(--color-card) 80%, transparent),
    color-mix(in srgb, var(--color-card) 40%, transparent));
  box-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.05);
  border: 1px solid var(--color-card);
}
.primary-button {                    /* primary-glow: a 9-layer color-matched shadow stack */
  background: var(--color-primary-cta);
  box-shadow:
    color-mix(in srgb, var(--color-background) 20%, transparent) 0 3px 1px 0 inset,
    color-mix(in srgb, var(--color-primary-cta) 15%, transparent) 0 0.84px 0.5px -0.3px,
    /* …ramps out to… */
    color-mix(in srgb, var(--color-primary-cta) 15%, transparent) 0 50px 30px -2.5px;
}
```
The `inset` top highlight + the color-matched glow ramp is what makes buttons look lit rather than flat.
Full stack in `assets/foundation.css`.

## 6. The 10 style skins — swap 3 blocks + radius + font

A "style" is nothing but a different `.card` / `.primary-button` / `.secondary-button` recipe plus a
radius and a font. **Palette and everything else stay identical.** Pick one, or invent your own by
recombining. All shadow/background values use `color-mix(... var(--color-*) ...)` so they auto-recolor.

| style | radius | font | `.card` signature | `.primary-button` signature |
|---|---|---|---|---|
| **glass** | 1.5rem | Inter Tight | blur(8px) gradient + 1px border | dual-inset highlight + soft glow |
| **minimal** | 0.5rem | Inter | flat + 6-layer micro-shadow, no border | solid, no shadow |
| **soft** | 1.5rem | DM Sans | flat + 6-layer micro-shadow | pillowy top+bottom inset gradient |
| **gradient** | 1.5rem | Poppins | stacked gradients + 2px border | vertical gradient + inset highlight |
| **neon** | 0.5rem | Montserrat | recessed inner-glow | solid + colored halo |
| **metallic** | 0.75rem | Inter Tight | inset glow | 5-stop chrome sweep |
| **shadow** | 0.75rem | Plus Jakarta Sans | glass card | 9-layer downward glow stack |
| **elegant** | 0.5rem | **Playfair** (serif) | outline only, no shadow | top-highlight gradient |
| **bold** | 0.5rem | Archivo | single 4px/32px shadow | glow stack thrown LEFT (negative x) |
| **elevated** | 0.75rem | Figtree | solid, no shadow/border (flattest) | clean doubling shadow ramp |

Three contrasting recipes verbatim (drop into your CSS, replacing the `.card`/`.primary-button` blocks):

```css
/* NEON — recessed inner glow */
.card { box-shadow:
  inset 0 0 30px 0 color-mix(in srgb, var(--color-foreground) 4%, transparent),
  inset 0 1px 0 0 color-mix(in srgb, var(--color-foreground) 8%, transparent),
  0 4px 12px -4px color-mix(in srgb, var(--color-foreground) 8%, transparent); }

/* MINIMAL / SOFT — 6-layer micro-shadow ramp, no border */
.card { background: var(--color-card); box-shadow:
  0 .7px .7px -.67px color-mix(in srgb, var(--color-primary-cta) 2%, transparent),
  0 1.8px 1.8px -1.3px color-mix(in srgb, var(--color-primary-cta) 3%, transparent),
  0 3.6px 3.6px -2px   color-mix(in srgb, var(--color-primary-cta) 3%, transparent),
  0 6.9px 6.9px -2.7px color-mix(in srgb, var(--color-primary-cta) 4%, transparent),
  0 13px 13px  -3.3px  color-mix(in srgb, var(--color-primary-cta) 4%, transparent),
  0 30px 30px  -4px    color-mix(in srgb, var(--color-primary-cta) 5%, transparent); }

/* ELEGANT — pure outline (pair with Playfair headings) */
.card { background: var(--color-card);
  border: 1px solid color-mix(in srgb, var(--color-foreground) 10%, transparent); }
```

## 7. Smoothness setup recap
- Lenis `<ReactLenis root>` at the app root (not CSS `scroll-behavior`).
- `html, body { overscroll-behavior: none; }` — kills the rubber-band bounce.
- Thin recolored scrollbar via `scrollbar-width: thin; scrollbar-color: … transparent;`.
- Mask-fade utilities (`.mask-fade-x`, `.mask-fade-y`, …) in `assets/masks.css` — feather the edges of
  marquees, carousels, and background layers so nothing hard-cuts.
- Keyframe library (marquee, aurora, orbit, spin-slow, floating, ray-pulse, progress) in `assets/animations.css`.
