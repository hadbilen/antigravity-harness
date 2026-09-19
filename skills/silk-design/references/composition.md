# Composition — assembling a page

How the sites are built above the effect level: the page skeleton, the section contract every section
follows, and the authoring rules that keep 100 sections feeling like one system.

## Page skeleton (assembly order)
```tsx
<ReactLenis root>                    {/* smooth scroll — once, at the top */}
  {/* optional: <SiteBackground position="fixed" /> behind everything */}
  <Navbar logo="BRAND" navItems={…} ctaButton={…} />
  <main>
    <section id="hero"     data-section="hero"><Hero … /></section>
    <section id="features" data-section="features"><Features … /></section>
    <section id="about"    data-section="about"><About … /></section>
    …pricing · testimonials · faq · cta…
  </main>
  <Footer brand="BRAND" columns={…} />
</ReactLenis>
```
- Each section gets an `id` (for anchor-scroll via `useButtonClick`/Lenis) + a `data-section` name.
- Sections take **flat content props** (`tag`, `title`, `description`, `primaryButton:{text,href}`,
  `items[]`, `imageSrc`/`videoSrc`, `textAnimation`) — no nested config objects.

## The section contract
Every section's inner content is centered in a content-width wrapper and animates in:
```tsx
<section aria-label="…" className="py-20">
  <div className="w-content-width mx-auto flex flex-col gap-8">
    {/* — canonical header — */}
    <div className="flex flex-col items-center gap-2 text-center">
      <div className="px-3 py-1 text-sm card rounded w-fit">{tag}</div>
      <TextAnimation tag="h2" variant={textAnimation} gradientText
        text={title} className="text-6xl 2xl:text-7xl font-semibold text-balance" />
      <TextAnimation tag="p" variant={textAnimation} gradientText={false}
        text={description} className="text-lg md:text-xl" />
      <div className="flex gap-3 mt-2">
        <Button text={…} href={…} variant="primary" />
        <Button text={…} href={…} variant="secondary" animationDelay={0.1} />
      </div>
    </div>
    {/* — body — */}
    <ScrollReveal variant="slide-up"> {/* grid or carousel of cards */} </ScrollReveal>
  </div>
</section>
```
This exact header pattern repeats across ~90% of sections — that repetition is what makes the sites feel
coherent. Secondary button always `animationDelay={0.1}` so it trails the primary.

## Responsive padding & gap scale (use verbatim)
- Card padding: `p-6 xl:p-7 2xl:p-8`
- Grid/flex gaps: `gap-4 xl:gap-5 2xl:gap-6`
- Section vertical rhythm: `py-20` (or `py-60` for a dramatic standalone moment).
- Titles are `font-semibold` (not medium); big numbers/stats `text-8xl`–`text-9xl font-semibold`.

## Grid-or-carousel rule
For a row of cards: **≤3 items → CSS grid; >3 → carousel** (Embla, `dragFree: true`, `cursor-grab`,
a `translate3d` progress bar + chevrons). Keeps small sets clean and large sets swipeable instead of cramped.
Edge case: exactly 4 items → grid on `2xl:` screens, carousel below (both rendered, toggled by breakpoint).

## Bento live widgets — what goes in the cells
A bento grid earns its keep when 2–3 cells *move*. The kit's widget menu (each is a self-contained
`h-full` component dropped into a card cell; recipes in effects.md where noted):
- **animated-bar-chart** — bars at preset heights; one "active" bar cycles every 3s (`primary-button`
  overlay fades in); hover swaps ALL bars to alternate heights (`transition-all duration-500`).
  Bottom-fade mask so it melts into the card.
- **chat-marquee** — fake live chat: alternating user/AI bubbles in a vertical marquee (`mask-fade-y`)
  over a static input row. Sells "AI product" instantly.
- **orbiting-icons** — center icon + icons on `animation: orbit 12s linear infinite` (keyframe in
  `animations.css`, per-icon `--initial-position: (360/n)*i deg`), concentric border rings at
  decreasing opacity, all inside `perspective: 2000px` + `rotateY(20deg) rotateX(20deg) rotateZ(-20deg)`
  for the 3D look, edge-masked with intersecting X+Y fades.
- **tilted-stack-cards** — three cards in one grid area (`[grid-template-areas:'stack']`), all
  `-skew-y-[8deg]`, offset by translates; hover nudges each apart (`duration-500`).
- **media-stack** — hover fan-out photo stack (effects.md).
- **checklist-timeline** — staged hover scene with utility delays (effects.md).
- **info-card-marquee / icon-text-marquee** — vertical tickers of stat/icon rows, `mask-fade-y`.
Pattern: widgets are pure CSS/keyframe motion (no scroll listeners), token-colored, and masked at
their edges so they read as *inside* the card, not pasted on.

## Navbar archetypes
`NavbarInline` (logo + links + CTA in a bar) · `NavbarCentered` (links centered) · `NavbarFloating`
(detached pill, `top-5`, card bg) · `NavbarFloatingLogo` (floating logo only) · `NavbarDropdown`
(inline + hover panels) · `NavbarCenteredOverlay` (transparent over hero) · `NavbarFullscreen`
(hamburger → fullscreen curtain menu — the premium option; recipe in effects.md + `assets/NavbarFullscreen.tsx`)
· `NavbarFullscreenStatic` (same, always hamburger). Pick ONE; floating pill for light/product sites,
fullscreen curtain for editorial/luxury/portfolio.

## Section archetype menu (what to reach for)
- **Hero** — split (text + media), billboard (full-bleed image + overlay), scroll-scrubbed video
  (`assets/HeroVideoScroll.tsx`), pinned card-stack, floating-cards, tilted carousel, **brand
  wordmark** (giant name spanning full width via `assets/AutoFillText.tsx`), sticker-flip
  (draggable stickers + 3D flip card — effects.md), stack-to-grid work reel (effects.md).
- **Features** — icon/media cards, **bento grid** (mixed-size cards with live mini-widgets — see
  "Bento live widgets" above), **pinned sticky cards** (scrub), 3D flip cards, alternating split,
  comparison table, filterable grid, image **reveal cards** (hover panel + expanding description).
- **About / editorial** — reading word-fill (`assets/AboutTextFill.tsx`), two-layer parallax, cursor
  image-trail (`assets/AboutCursorTrail.tsx`), text+media split.
- **Testimonials** — dual-row horizontal marquee, vertical column marquee, avatar/quote/rating cards.
- **Pricing** — highlighted plan (ribbon), centered/simple/split/layered cards.
- **FAQ** — single-open accordion (`AnimatePresence`, `height: 0 → auto`, `opacity 0→1`, `duration 0.3`,
  Plus-icon `rotate-45` on open), two-column, tabbed.
- **Metrics** — big-number stat cards. **Social proof** — single-row logo/name marquee.
- **CTA / contact** — centered CTA, split form (+ parallax), contact bar.
- **Footer** — reveal-from-behind (`assets/FooterBrandReveal.tsx`), brand wordmark, simple columns.

## Authoring rules (why 100 sections still feel like one system)
Follow these when you write sections:
- **Flat > nested, explicit > implicit.** One file per section, content variables at the top. Don't split
  a section into sub-components. Keep sections under ~100 lines, UI primitives under ~50.
- **Single default export** per file. No compound components, no `className` prop drilling — edit classes in-file.
- **Framer Motion `whileInView` for element animation; GSAP only for scroll-scrub / pin / timeline work**
  (scrubbed video, cursor trail, pinned stacks). Don't reach for GSAP when a `whileInView` does it.
- **Class order:** layout → spacing → sizing → typography → colors → effects. (Consistent, greppable.)
- Media from a CDN, never committed. `object-cover` + a fixed `aspect-*` box so images never jump.
- One animated background per page, low opacity. One button hover-personality per site.
