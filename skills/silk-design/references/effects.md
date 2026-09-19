# Effects catalog — exact configs

Every config below is a tuned default. The numbers carry the feel — use them as given unless you
have a reason not to. Group: entrance · scroll-driven · cursor/pointer · hover · marquees/carousels ·
navigation & page transitions · loaders.

---

## Entrance reveals

### Word-stagger heading — `assets/TextAnimation.tsx`
Splits text on spaces, reveals each word with a stagger. The signature heading animation.
- Container: `whileInView`, `viewport={{ once: true, margin: "-20%" }}`, `transition={{ staggerChildren: 0.04 }}`.
- Per word: `transition={{ duration: 0.6, ease }}`.
- Variants: `slide-up` (`y: "50%"→0`, ease `[0.25, 0.46, 0.45, 0.94]`), `fade-blur` (`blur(10px)→none`, ease `[0.45, 0, 0.55, 1]`), `fade`.
- Optional gradient text-clip fills in ~700ms after the reveal (`from-foreground to-primary-cta bg-clip-text text-transparent`).

### Block reveal — `assets/ScrollReveal.tsx`
Wrap any block; it fades/slides in once when scrolled into view.
- `whileInView`, `viewport={{ once: true, margin: "-20%" }}`, `transition={{ duration: 0.6, delay, ease: "easeOut" }}`.
- `slide-up` = `y: 20→0`. Stagger siblings by passing increasing `delay` (0, 0.1, 0.2…).

**The margin `-20%` matters:** it fires the reveal when the element is 20% into the viewport, not at
the very edge — so content is already moving before the user reaches it. `once: true` = never re-hide.

---

## Scroll-driven effects

### Parallax (two-layer depth) — `motion/react`
Layers move at different rates as the section scrolls past. Principle: map scroll progress → transform.
```tsx
const { scrollYProgress } = useScroll({ target: ref, offset: ["start end", "end start"] });
const yFront = useTransform(scrollYProgress, [0, 1], [120, -120]);   // front layer
const yBack  = useTransform(scrollYProgress, [0, 1], [-60, 60]);     // back layer
const scale  = useTransform(scrollYProgress, [0, 1], [1, 1.15]);     // subtle zoom
// <motion.img style={{ y: yFront }} />  … style={{ y: yBack, scale }}
```

### Reading word-fill — `assets/AboutTextFill.tsx`
Big paragraph where each word brightens `0.15 → 1` opacity as you scroll through it (premium editorial feel).
- `useScroll({ target, offset: ["start 0.8", "start 0.2"] })`.
- Per word `i` of `n`: `useTransform(scrollYProgress, [i/n, (i+1)/n], [0.15, 1])`.

### Scroll-scrubbed video — `assets/HeroVideoScroll.tsx` (GSAP)
Video scrubs frame-by-frame as you scroll — feels like a controlled cinematic. The showstopper hero.
- Outer `h-[300vh]`, inner `sticky top-0 h-svh`.
- `ScrollTrigger.create({ trigger, start: "top top", end: "bottom bottom", scrub: 0.5, onUpdate: self => { video.currentTime = video.duration * self.progress } })`.
- Video: `muted playsInline preload="auto"`. Wait for `canplaythrough` (8s fallback) before wiring.
- Includes a clip-path loader (see Loaders) and content entrance `opacity:0,y:30 → dur 0.8, delay 0.2/0.4, ease [0.22, 1, 0.36, 1]`.

### Pinned + scrubbed card stack — GSAP ScrollTrigger
Section holds still while inner cards animate on scroll. Principle: tall section + `sticky` inner + scrub.
- Section height `= items.length * 100vh`; inner `sticky top-0 h-screen`.
- Per card: `gsap.fromTo(card, { xPercent: ±225, rotation: ±45 }, { xPercent: 0, rotation: ±10, scrollTrigger: { trigger, start: "top bottom", end: "top top", scrub: 1 } })`.
- Or fade a stack out one-by-one: `sticky top-[12.5vh] h-[75vh]`, scrub `opacity → 0`, `ease: "none"`.

### Hero exit-parallax (scroll-away)
The hero's media drifts down and zooms as you scroll *off* it — the "leave-behind" counterpart to
section parallax. Used by several kit heroes (`HeroExpand`, `HeroOverlayParallax`):
```tsx
const { scrollYProgress } = useScroll({ target: heroRef, offset: ["start start", "end start"] });
const y     = useTransform(scrollYProgress, [0, 1], ["0px", "150px"]);
const scale = useTransform(scrollYProgress, [0, 1], [1, 1.1]);
// <motion.div className="absolute inset-0" style={{ y, scale }}><media/></motion.div>
```
Variant — **floating gutter cards**: small cards absolutely positioned in the content-width gutter
(`left-[calc((100vw-var(--width-content-width))/2)]`) with `y: "0%" → "-100%"` / `"-75%"` on the same
offset, so they float up past the hero at different rates.

### Tilt-flatten billboard — 3D perspective on scroll
Hero media starts tilted back in 3D and flattens as it scrolls into view (the "container scroll" look).
Wrapper gets Tailwind `perspective-distant`; the media card:
```tsx
const { scrollYProgress } = useScroll({ target: containerRef });
const rotate = useTransform(scrollYProgress, [0, 1], [20, 0]);   // rotateX
const scale  = useTransform(scrollYProgress, [0, 1], [1.05, 1]);
// <motion.div style={{ rotateX: rotate, scale }} className="card rounded overflow-hidden">
```
Mobile: skip the JS, ship a static `rotate-x-20`.

### Stack-to-grid scroll (FLIP-style) — GSAP
Cards start stacked/fanned inside the hero, then scrub back into their natural grid slots in the next
section as you scroll (`HeroWorkScrollStack`, the portfolio showcase). The trick: **measure, then
transform** — cards live in their final grid position in the DOM; compute the delta to the hero
placeholder and set it as the initial transform.
- `yOffset = placeholderCenterY - cardCenterY` (from `getBoundingClientRect`), plus per-card
  `x` offsets, `rotation: [-5, 0, 5]`, `scale: ~1.3`, staggered `zIndex`.
- Desktop: one timeline, `scrollTrigger: { trigger: wrapper, start: "top top", end: "bottom bottom", scrub: 1 }`,
  each card `tl.to(card, { x: 0, y: 0, rotation: 0, scale: 1 }, 0)`.
- Mobile: same `gsap.set`, but a plain tween with `scrollTrigger: { start: "top 35%", toggleActions: "play none none reverse" }`.
- Always `gsap.set(card, { willChange: "transform", force3D: true })` first.

### Footer reveal-from-behind — `assets/FooterBrandReveal.tsx`
Page content scrolls up like a sheet, uncovering a fixed footer sitting underneath. No JS scroll math.
- Outer `section`: `position: relative`, `clipPath: polygon(0 0, 100% 0, 100% 100%, 0 100%)` (creates a clip
  context), height set to the footer's measured height (ResizeObserver).
- Inner footer: `position: fixed; bottom: 0`. Because the section clips, the footer only shows as page
  scrolls past. Pair with a giant auto-fitting wordmark (`AutoFillText`, canvas-measured to span full width).

---

## Cursor & pointer

### Magnetic button — `assets/ButtonMagnetic.tsx`
Button leans toward the cursor when hovered. Subtle, expensive-feeling.
- `useSpring(useMotionValue(0), { stiffness: 150, damping: 15 })` for x and y.
- On mousemove: `offset = (cursor - center) * 0.15`; on leave: reset to 0.
- **Disabled below 768px** (`window.innerWidth < 768`) — no cursor on touch.

### Cursor image-trail — `assets/AboutCursorTrail.tsx` (GSAP, the showpiece)
Moving the cursor drops a trail of images that fade out — the "move your cursor!" moment.
- `gsap.matchMedia()`: desktop = mousemove, mobile = scroll-driven random placement.
- Fires when the cursor moves more than `window.innerWidth / 15` since the last drop.
- Drop: `gsap.set(img, { x, y, zIndex, force3D })` then `fromTo(img, { autoAlpha: 0, scale: 0.8 }, { autoAlpha: 1, scale: 1, duration: 0.2, overwrite: true })`.
- Idle fade after 350ms: `gsap.to(img, { autoAlpha: 0, scale: 0.2, duration: 0.8, ease: "expo.out" })`.
- Gated by `ScrollTrigger.create({ start: "top bottom", end: "bottom top", onEnter/onLeave })` so it only runs while on screen. Always `mm.revert()` in cleanup.

### Pointer-tracked border glow — `assets/BorderGlow.tsx`
A conic-gradient segment lights up the card's border and rotates toward the cursor. The premium
"lit edge" for feature cards (drop inside any `relative rounded` card).
- CSS vars drive it: `--start` (angle), `--active` (0/1), `--spread: 40`, `--border-width: 1.5px`.
- On pointermove (rAF-throttled, one listener on `body`): activate when cursor is within `proximity: 64px`
  of the card rect; compute `targetAngle = atan2(y-cy, x-cx) + 90°`, then animate `--start` there with
  motion's `animate(current, target, { duration: 2, ease: [0.16, 1, 0.3, 1] })` (shortest-path via
  `((diff+180)%360)-180`).
- The visible ring is an `::after` with a token gradient, masked to a conic slice:
  `mask: linear-gradient(#0000,#0000), conic-gradient(from calc((var(--start)-var(--spread))*1deg), transparent, #fff, transparent …)`
  + `[mask-clip:padding-box,border-box]` + `mask-intersect` — only the border area shows, only in the slice.

### Cursor-mask character pattern — `assets/HoverPattern.tsx`
Hovering a card reveals a drifting field of random characters + an accent gradient through a radial
mask that follows the cursor — the "encrypted" hover.
- `useMotionValue` x/y + `useMotionTemplate` mask: `radial-gradient(250px at ${x}px ${y}px, white, transparent)`.
- Three stacked layers, all `opacity-0 group-hover:opacity-*`: a faint `linear-gradient(var(--foreground), transparent)`
  wash (25%), an accent gradient + `backdrop-blur-xl` (masked), and a `mix-blend-overlay` layer with
  1500 random chars in `font-mono text-xs` (masked; regenerate chars on each mousemove).
- Mobile: pin the mask to center at 110px, always-on, no listeners.

### Draggable stickers — GSAP Draggable
Scattered sticker images the user can fling around the hero (`HeroStickerFlip`, the playful showcase).
- Entrance: `gsap.fromTo(el, { autoAlpha: 0, scale: 0.5, y: 30 }, { autoAlpha: 1, scale: 1, y: 0, duration: 0.6, delay: 0.8 + i * 0.08, ease: "back.out(2)" })`.
- `Draggable.create(el, { type: "x,y", bounds: container, dragResistance: 0.1 })`;
  onPress `scale: 1.15, rotation: (Math.random()-0.5)*20, ease: "power2.out"`; onRelease
  `scale: 1, rotation: 0, duration: 0.5, ease: "back.out(3)"` — pick up, wiggle, snap back.
- Scatter via a positions table (`top/left/right/bottom %` + `rotate ±4–14deg`), `drop-shadow-lg`,
  `cursor-grab active:cursor-grabbing`. Register `gsap/Draggable`; wrap in `gsap.context`, revert on cleanup.

---

## Hover micro-interactions — 12 button variants

All share the entrance `initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ duration: 0.6, ease: "easeOut" }}`. Pick per site for a consistent hover personality:

- **expand** — a fill panel slides in from the left on hover (`-translate-x-full → translate-x-0`, `duration-500 ease-out`), text color swaps primary↔secondary. The default; safe and classy.
- **magnetic** — leans toward cursor (above).
- **slide / shift** — label + arrow slide together on hover.
- **stagger** — each character rolls up (`translateY(-1.25em)` with a `textShadow: 0 1.25em currentColor` trick to fake a second copy), `transitionDelay: index * 0.01`.
- **bounce / elastic / bubble / flip / pill / arrow** — spring/rotate/scale flourishes on the icon or label.

Principle for any of them: a `group` wrapper + `transition` on a child that reacts to `group-hover:`.
Keep durations 300–500ms and easings gentle; the point is polish, not spectacle.

## Hover micro-interactions — beyond buttons

### The grid-fr expand trick (animate to `auto` size, pure CSS)
CSS can't transition `width/height: auto` — but it CAN transition grid fractions. Wrap the content:
```html
<div class="grid grid-cols-[0fr] group-hover:grid-cols-[1fr] transition-all duration-500 ease-out">
  <div class="overflow-hidden">…content…</div>
</div>
```
Same for height: `grid-rows-[0fr] group-hover:grid-rows-[1fr]`. The kit uses it for a button that
grows a second avatar on hover, and for card descriptions that expand below the title. Pair the inner
content with its own `-translate-x-3 group-hover:translate-x-0` + opacity for a directional feel.

### Image reveal card (`FeaturesRevealCards`)
Full-bleed image card; on hover a panel slides up behind the caption and the description expands:
- Frosted scrim: bottom strip `h-2/5 backdrop-blur-xl` masked with `mask-image: linear-gradient(to bottom, transparent, black 60%)` — blur fades in, no hard edge.
- Panel: `absolute inset-0 -z-10 card rounded translate-y-full opacity-0 → group-hover:translate-y-0 opacity-100`, `duration-400 ease-out`.
- Description: the grid-rows-fr trick above. Title swaps `text-white → text-foreground`.

### 3D flip card (Tailwind v4 utilities, no JS beyond a toggle)
```tsx
<div className="perspective-[3000px] cursor-pointer" onClick={() => setFlipped(!flipped)}>
  <div data-flipped={flipped} className="relative transform-3d transition-transform duration-500 data-[flipped=true]:transform-[rotateY(180deg)]">
    <div className="card backface-hidden">…front…</div>
    <div className="absolute inset-0 card backface-hidden transform-[rotateY(180deg)]">…back…</div>
  </div>
</div>
```
Front corner: `Plus` icon; back: same icon `rotate-45` (= ×). For a big hero flip use hover to toggle
and a bouncy `duration-1200 ease-[cubic-bezier(0.22,0.68,0,1.2)]` — the overshoot sells it.

### Hover fan-out stack (`MediaStack`)
Three overlapping media cards fanned `±rotate-8` + translate; on `group-hover` each pushes further
out (`rotate-12`, larger translate), `duration-500`. Cheap depth, great in bento cells.

### Staged hover scene (`ChecklistTimeline`)
A hover can play a little *sequence* with nothing but utility delays: checkmarks pop in at
`delay-150/-[350ms]/-[550ms]` (`opacity-0 scale-75 → 100`), labels fade behind each
(`delay-200/-[400ms]/-[600ms]`), a loader icon spins (`group-hover:rotate-360 duration-1000`), and at
`delay-900` the footer dots swap to a "completed" label. One `group`, zero JS.

---

## Marquees & carousels — `assets/animations.css` + `assets/masks.css`
Infinite horizontal/vertical scroll (logos, testimonials, tags). Pure CSS, no JS.
- Duplicate the item array **4×** inside an `overflow-hidden` track, apply `.animate-marquee-horizontal`.
- Keyframe translates `0 → -50%` (that's why you duplicate — the second copy fills the gap seamlessly).
- Feather both ends with `.mask-fade-x` so items don't hard-cut at the edges.
- Speeds: horizontal default `15s`, vertical `40s`; override per-row via inline `style={{ animationDuration: "30s" }}`. Run two rows in opposite directions (`-reverse` variant) for a richer feel.
- The marquee is also a **widget chassis**: fake live chat (alternating bubbles in a card, marquee-vertical
  + `mask-fade-y` + a static input row below), info/stat tickers, before/after card streams (slow, `60s`).

### Deck carousel (`TiltedCarousel`) — the 3D-ish auto-rotating deck
Five slots `[-2,-1,0,1,2]`, item index = `(active + position + n) % n`. Per slot:
`scale 1 / 0.88 / 0.8`, `x = position*100%`, `y = 0 / 5% / 10%`, `rotate = position*2°`, `opacity 0`
beyond ±1. Animate all with `duration 0.8, ease: [0.65, 0, 0.35, 1]`; z-index center-first.
Non-center cards get a `bg-background/50 backdrop-blur-[1px]` overlay so the center pops. Autoplay 4s.

### Focus loop carousel (Embla)
`useEmblaCarousel({ loop: true, align: "center" })`; inactive slides `opacity-70 scale-90`, active
`opacity-100 scale-100`, `transition-all duration-500` — a center-stage loop for testimonials/media.
(The standard row carousel — `dragFree: true`, progress bar, chevrons — is in composition.md.)

### Fanned card row (`HeroTiltedCards`)
Static gallery that reads as 3D: 5 cards, alternating `±rotate-6` and `±translate-y-5`, overlapped
with `-ml-15`, ascending z-index, `hover:scale-110 duration-500`. Mobile: swap to a marquee.

### Filter-swap animation (`FeaturesFilterGrid`)
When a filter changes, don't re-sort in place — remount the grid with `<AnimatePresence mode="wait">`,
key = active filter, and re-stagger the children (`staggerChildren` variants). The blink of motion
reads as the grid "answering" the click.

---

## Navigation & page transitions

### Fullscreen curtain menu — `assets/NavbarFullscreen.tsx`
The premium mobile/desktop menu: a full-viewport curtain drops from the top edge, oversized links
rise in one by one. All the coordination details matter:
- Curtain: `clip-path` polygon from zero-height top edge to full —
  `polygon(0% 0%, 100% 0%, 100% 0%, 0% 0%)` → `polygon(0% 0%, 100% 0%, 100% 100%, 0% 100%)`,
  `transition-[clip-path] duration-700 ease-[cubic-bezier(0.9,0,0.1,1)]`. Background `bg-foreground`
  (inverted), so the logo swaps `text-foreground ↔ text-background` in sync.
- Links: `text-7xl md:text-9xl` inside `overflow-hidden`; `translateY(100%) → 0`,
  `transition: transform 0.5s cubic-bezier(0.7, 0, 0.3, 1)`, open delay `0.3 + i*0.05`s,
  **close delay reversed** (`(n-1-i)*0.05`) so they exit bottom-up. Hairline `bg-background/20` dividers.
- Link hover: label `group-hover:ml-4`, arrow `ArrowUpRight` `group-hover:rotate-45` — 300ms.
- Hamburger→X: two `w-3 h-px` spans, `-translate-y-1`/`translate-y-1` ↔ `rotate-45`/`-rotate-45`.
- Hygiene: `document.body.style.overflow = "hidden"` while open, Escape closes, nav itself is
  `fixed inset-0 pointer-events-none` with `pointer-events-auto` only on the bar + curtain.

### Page-transition swirl — `assets/PageTransitionSwirl.tsx` (GSAP DrawSVGPlugin)
A brand-colored SVG spiral covers the viewport and "unwinds" itself away on page mount:
- One long spiral `<path>` in a fixed `inset-0 z-50 pointer-events-none` layer, `stroke="currentColor"`
  on a `text-primary-cta` wrapper, svg oversized `w-[130%] -top-[15%]` with `preserveAspectRatio="none"`.
- `gsap.set(path, { strokeWidth: "35%", drawSVG: "0% 100%" })` then
  `gsap.to(path, { drawSVG: "100% 100%", strokeWidth: "5%", duration: 1.25, ease: "power1.inOut", delay: 0.3 })`
  — the stroke thins as it erases, which is what makes it feel liquid. Register `gsap/DrawSVGPlugin`.
- Mount it on route change (key it by pathname) for an instant "crafted" page swap.

---

## Loaders & clip-path reveals

### Clip-path wipe loader — in `assets/HeroVideoScroll.tsx`
A full-screen loader that wipes the brand name in, then lifts away.
- Text reveal: `clipPath: "inset(0% 100% 0% 0%)" → "inset(0% 0% 0% 0%)"`, `transition={{ duration: 2, ease: [0.76, 0, 0.24, 1] }}`.
- Progress bar: `scaleX: 0 → 1`, `originX: 0`.
- On complete: `AnimatePresence` exit `opacity: 0`, `duration 0.8, ease [0.76, 0, 0.24, 1]`.

### Clip-path expand reveal
Loader panel that opens from an inset rounded rectangle to full-bleed:
`clipPath: "inset(25% 20% 25% 20% round 24px)" → "inset(0% round 0px)"`, `duration 1.4, ease [0.76, 0, 0.24, 1]`.

### Brand panel loader (`LoaderReveal`)
Solid `bg-background-accent` panel with logo + clip-path name wipe (3s), and a bottom progress bar
with a signature detail: it **fills from the left** (`scaleX 0→1, originX: 0`, 3s) then **retracts to
the right** (`originX: 1`, `scaleX→0`, 0.5s) before the whole panel exits `y: "-101%"`,
`duration 1, ease [0.76, 0, 0.24, 1]`. Fill→retract→lift reads far better than a fade.

**Signature easings worth reusing:** `[0.76, 0, 0.24, 1]` (dramatic in-out, for wipes/loaders),
`[0.22, 1, 0.36, 1]` (soft overshoot-free ease-out, for content entrances), `[0.25, 0.46, 0.45, 0.94]`
(the slide-up default), `[0.16, 1, 0.3, 1]` (long luxurious settle — border glow, slow hero text),
`[0.9, 0, 0.1, 1]` (hard curtain snap, for fullscreen menus), `[0.65, 0, 0.35, 1]` (symmetric
in-out, for carousel slides), `[0.22, 0.68, 0, 1.2]` (playful overshoot, for 3D flips),
`expo.out` / `back.out(2–3)` (GSAP, snappy fades / sticker pops).
