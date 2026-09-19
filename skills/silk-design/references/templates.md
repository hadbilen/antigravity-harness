# silk — template references

23 worked reference compositions built from **this exact toolbox**. Pull one up as a starting
point: a coherent palette + font + section rhythm + effect set that already hangs together.
Triggered by `/silk-design Reference7` or "build this like the cream-and-espresso one". A number
resolves directly; a described mood resolves against the vibe line of each row.

## The contract — reference, don't clone
A referenced site is a **mood-board + wireframe, not a source file.** Take its **skin** and
**skeleton**; never its **flesh.**

- **Skin — take it:** palette, font, radius, card/button style, hero background, hover +
  text-animation, the signature effects.
- **Skeleton — take it loosely:** the section *rhythm* (the flow listed per site) as a
  starting sequence, re-ordered and trimmed to fit the real content. Not a pixel-copy of any
  layout.
- **Flesh — off-limits:** copy, images, brand, business specifics, and 1:1 layout. The new
  site has its own subject — write and lay it out for that.

The built-in foundation (Lenis root, 9-token system, fluid type, the one reveal config)
always applies underneath — see `SKILL.md`. The referenced site only decides the *look* and
*rhythm* on top of it.

## How to read a row
`ReferenceN` — vibe. Then palette / type / skin, the section **Flow**, and
the **Signature** effects worth stealing. Type is **Inter** (body) + **Inter Tight**
(headings) unless a row says *"Inter Tight throughout"* (a tighter, more editorial feel).
Every row is self-contained. For the full 9-token palette and the exact card/button CSS behind a
row's skin, read `templates/ReferenceN/theme.css` — a palette, a font, and three CSS recipes.
All compositions assume React + Vite + Tailwind v4 + motion + GSAP + Lenis.

---

## Trades & home services

**`Reference1`** — dark, high-gloss, confident.
Palette **dark**: bg `#0a0a0a` · fg `#f5f5f5` · cta+accent `#ff7a1a` (premium orange). Skin: soft radius `1.5rem` · glass-elevated cards · gradient/glass buttons · hover *expand* · text *slide-up*.
Flow: NavbarCentered → HeroBillboardFeatures → FeaturesStickyCards → TestimonialMarqueeOverlayCards → FeaturesComparison → TeamOverlayCards → FaqSimple → ContactSplitForm → FooterSimpleCard.
Signature: `lightRaysCenter` hero glow · pinned **sticky feature cards** · testimonial marquee.

**`Reference2`** — clean, trustworthy, corporate blue.
Palette **light**: bg `#f8fafc` · fg `#0f172a` · cta `#1d4ed8` · accent `#3b82f6`. Skin: soft radius `1.5rem` · glass-elevated cards · gradient/glass buttons · hover *arrow* · text *slide-up*.
Flow: NavbarInline → HeroOverlay → AboutFeaturesSplit → FeaturesMediaCards → FeaturesAlternatingSplit → FeaturesTimelineCards → TestimonialRatingCards → FaqSimple → ContactCta → FooterSimpleMedia.
Signature: media-overlay hero · **alternating split** features · timeline cards.

**`Reference3`** — fresh, natural, grounded.
Palette **light**: bg `#f7f9f4` · fg `#1a2e1a` · cta `#2d5a27` · accent `#4a8c3f` (garden green). Skin: soft radius `1.5rem` · glass-elevated cards · gradient/glass buttons · hover *stagger* · text *slide-up*.
Flow: NavbarCentered → HeroOverlayTestimonial → AboutTestimonial → FeaturesDetailedSteps → TeamGlassCards → TeamOverlayCards → TestimonialAvatarCard → FaqTwoColumn → ContactSplitForm → FooterSimple.
Signature: hero w/ overlaid testimonial · detailed **step** features · glass team cards.

**`Reference4`** — dark, technical, dependable.
Palette **dark**: bg `#020617` · fg `#f1f5f9` · cta `#0ea5e9` · accent `#38bdf8` (sky). Skin: soft radius `1.5rem` · glass-elevated cards · radial-glow/corner-glow buttons · hover *expand* · text *slide-up*.
Flow: NavbarInline → HeroCenteredLogos → FeaturesMediaCards → TestimonialRatingCards → FeaturesBorderGlow → FaqSimple → ContactSplitForm → FooterSimpleCard.
Signature: centered hero w/ logo strip · **border-glow** feature cards · corner-glow buttons.

**`Reference5`** — dark, rugged, warm.
Palette **dark**: bg `#1c1917` · fg `#fafaf9` · cta `#ea6720` · accent `#f97316` (burnt orange). Skin: soft radius `1.5rem` · glass-elevated cards · radial-glow/corner-glow buttons · hover *elastic* · text *slide-up*.
Flow: NavbarCentered → HeroBillboard → AboutFeaturesSplit → FeaturesRevealCards → MetricsMediaCards → FeaturesDetailedCards → TestimonialOverlayCards → FaqTwoColumn → ContactSplitForm → FooterSimple.
Signature: billboard hero · **reveal cards** · metrics-over-media cards.

## Health, beauty & wellness

**`Reference6`** — soft, clinical, luxe.
Palette **light**: bg `#fdf8f8` · fg `#2d1f2b` · cta+accent `#d5799b` (rose). Skin: soft radius `1.5rem` · soft-shadow cards · gradient/glass buttons · hover *arrow* · text *fade-blur*.
Flow: NavbarCentered → HeroOverlayMarquee → TeamGlassCards → FeaturesResultsComparison → TestimonialTrustCard → TeamOverlayCardsGrid → FaqSimple → ContactSplitForm → FooterSimpleCard.
Signature: hero **overlay marquee** · before/after **results comparison** · glass team cards.

**`Reference7`** — bright, precise, reassuring.
Palette **light**: bg `#f7f6f7` · fg `#0c1325` · cta `#0798ff` · accent `#93c7ff`. Skin: soft radius `1.5rem` · soft-shadow cards · radial-glow/soft-shadow buttons · hover *stagger* · text *slide-up*.
Flow: NavbarInline → HeroSplitKpi → ProductRatingCards → AboutText → FeaturesMediaCards → TestimonialMarqueeCards → ContactSplitEmail → FooterSimple.
Signature: **`horizonGlow`** hero backdrop · split hero with **KPIs** · testimonial marquee.

**`Reference8`** — warm, data-driven, human.
Palette **light warm**: bg `#fafaf9` · fg `#0c0a09` · cta `#ea6720` · accent `#f59e0b` (amber). *Inter Tight throughout.* Skin: rounded radius `1.5rem` · hover *magnetic* · text *slide-up* · display font **Geist**.
Flow: NavbarFloating → HeroOverlayStatistics → FeaturesMediaSimple → FeaturesAlternatingSplit → PricingHighlightedCards → BlogMediaCards → FaqSimple → FooterSimpleMedia.
Signature: hero with live **statistics overlay** · **magnetic** buttons · highlighted pricing.

**`Reference9`** — warm sand, organic, calm.
Palette **light**: bg `#fcf6ec` · fg `#2e2521` · cta `#2e2521` · accent `#b2a28b` (clay). Skin: soft radius `1.5rem` · glass-elevated cards · gradient/glass buttons · hover *shift* · text *fade*.
Flow: NavbarFloating → HeroBillboardBrand → AboutTextSplit → ProductMediaCards → FeaturesBento → TestimonialTrustCard → FaqSplitMedia → ContactCenter → FooterSimpleCard.
Signature: oversized **brand-name hero** · bento features · split-media FAQ.

## AI & SaaS

**`Reference10`** — dark, enterprise, neon-mint.
Palette **dark**: bg `#0a0a0a` · fg `#eeeded` · cta `#00FFAB` (mint) · accent `#737373`. Skin: radius `2rem` · hover *arrow* · text *slide-up*.
Flow: NavbarCentered → HeroBillboardScroll → FeaturesBento → FeaturesBorderGlow → AboutText → PricingLayeredCards → TeamOverlayCards → ContactCenter → FooterSimpleReveal.
Signature: `lightRaysCenter` hero · **scroll-driven billboard hero** · layered pricing cards · **footer reveal**.

**`Reference11`** — light blue, crisp, product-y.
Palette **light**: bg `#f8fafc` · fg `#0f172a` · cta `#106FEB` · accent `#B4D4F8`. Skin: rounded radius `1.5rem` · glass-glow cards · radial-glow/glass buttons · hover *expand* · text *fade-blur*.
Flow: NavbarDropdown → HeroBillboardFloatingCards → FeaturesGridSplit → FeaturesMediaCards → MetricsFeatureCards → PricingLayeredCards → TestimonialDetailedCards → FaqTwoColumn → BlogSimpleCards → ContactCta → FooterSimple.
Signature: **floating-cards hero** · glass-glow cards · layered pricing.

**`Reference12`** — light red, punchy, creator-energy.
Palette **light**: bg `#fffafa` · fg `#1a0000` · cta `#e63946` · accent `#f5c4c7`. Skin: rounded radius `1.5rem` · glass-elevated cards · radial-glow/glass buttons · hover *bounce* · text *fade-blur*.
Flow: NavbarFloating → HeroBillboardCreator → MetricsIconCards → TestimonialColumnMarqueeCards → FeaturesAlternatingSplit → PricingHighlightedCards → FaqTwoColumn → FooterSimpleMedia.
Signature: creator hero · vertical **column-marquee** testimonials · bounce buttons.

**`Reference13`** — dark purple, sleek, technical.
Palette **dark**: bg `#050012` · fg `#f0e6ff` · cta `#c89bff` (lilac) · accent `#684f7b`. Skin: soft radius `1.5rem` · glass-glow cards · radial-glow/glass buttons · hover *arrow* · text *slide-up*.
Flow: NavbarInline → HeroCenteredLogos → FeaturesBento → FeaturesIconCards → TestimonialTrustCard → PricingLayeredCards → ContactCta → FooterSimpleReveal.
Signature: `lightRaysCenter` glow · centered hero w/ logo strip · bento features · **footer reveal**.

## Real estate, hospitality & travel

**`Reference14`** — light, gold, premium.
Palette **light**: bg `#f0f0f0` · fg `#1a1a1a` · cta `#1a1a1a` · accent `#c89b3c` (gold). Skin: soft radius `1.5rem` · glass-elevated cards · gradient/glass buttons · hover *magnetic* · text *slide-up*.
Flow: NavbarFloating → HeroTiltedCards → AboutMediaOverlay → ProductVariantCards → FeaturesRevealCards → TeamOverlayCards → MetricsIconCards → TestimonialSplitCards → ContactCta → FooterBasic.
Signature: **`gradientBars`** hero bg · **3D tilted-cards hero** · magnetic buttons · media-overlay about.

**`Reference15`** — light, warm, cinematic.
Palette **light**: bg `#faf8f5` · fg `#1a1a1a` · cta `#1a1a1a` · accent `#c9a96e` (warm gold). *Inter Tight throughout.* Skin: soft radius `0.75rem` · hover *stagger* · text *fade* · display font **Cormorant Garamond**.
Flow: NavbarFullscreenStatic → HeroVideoScroll → AboutTextFill → FeaturesMediaColumns → ContactParallaxCard → FooterBasic.
Signature: **scroll-scrubbed video hero** (`HeroVideoScroll`) · **reading word-fill** (`AboutTextFill`) · parallax contact card. *The showcase for silk's premium scroll effects.*

**`Reference16`** — dark, hushed, champagne luxury.
Palette **dark**: bg `#0f1010` · fg `#f5f0eb` · cta `#ffffff` · accent `#d4b896` (champagne). *Inter Tight throughout.* Skin: rounded radius `1rem` · subtle-dark cards · white/subtle-dark buttons · hover *default* · text *slide-up* · display font **Playfair Display**.
Flow: NavbarFullscreen → HeroExpand → AboutParallax → FeaturesAttributeCards → FeaturesMediaGrid → FeaturesRevealCardsBento → FooterBrand → ContactSplitForm.
Signature: **expanding hero** (`HeroExpand`) · **parallax** about · reveal-cards bento · big-brand footer.

**`Reference17`** — warm beige, editorial, indulgent.
Palette **light**: bg `#f6f0e9` · fg `#3d1f2a` · cta `#3d1f2a` · accent `#8c4a5c` (wine). Skin: soft radius `1.5rem` · solid cards · shadow/solid buttons · hover *arrow* · text *fade*.
Flow: NavbarInline → HeroBrandCarousel → AboutText → FeaturesMediaCards → FeaturesDetailedSteps → FeaturesTaggedCards → TestimonialSplitCards → ContactSplitForm → FooterMinimal.
Signature: **`cornerGlow`** hero · **brand carousel** hero · tagged feature cards.

## Portfolio, blog & agency

**`Reference18`** — clean white, monochrome, confident.
Palette **light**: bg `#ffffff` · fg `#171717` · cta+accent `#171717` (mono). *Inter Tight throughout.* Skin: rounded radius `1rem` · subtle cards · solid-dark/subtle buttons · hover *stagger* · text *fade*.
Flow: NavbarFloatingLogo → TestimonialTrustCard → HeroWorkScrollStack → AboutTestimonialParallax → FeaturesBentoGridCta → FaqTabbedAccordion → ContactSplitFormParallax → FooterMinimal.
Signature: **`HeroWorkScrollStack`** (GSAP scroll-stacking work reel) · **parallax** testimonial + contact form. *The portfolio scroll showcase.*

**`Reference19`** — dark monochrome, bold, kinetic.
Palette **dark**: bg `#0a0a0a` · fg `#f0f0f0` · cta `#ffffff` · accent `#d0d0d0`. Skin: soft radius `1.5rem` · hover *stagger* · text *fade-blur*.
Flow: NavbarDropdown → HeroSplitVerticalMarqueeTall → FeaturesBento → FeaturesMediaCarousel → FeaturesBorderGlow → TestimonialTrustCard → MetricsFeatureCards → TeamStackedCards → FaqSimple → ContactCenter → FooterSimpleReveal.
Signature: **`lightRaysCorner`** glow · **tall vertical marquee** hero · media carousel · stacked team cards · footer reveal.

**`Reference20`** — warm, playful, personal.
Palette **light**: bg `#f5f3f0` · fg `#1a1a1a` · cta `#1a1a1a` · accent `#4CAF50` (green pop). *Inter Tight throughout.* Skin: rounded radius `1.5rem` · hover *bounce* · text *fade* · display font **Caveat**.
Flow: HeroStickerFlip → FeaturesBentoGridCta → FeaturesCarouselMarquee → FeaturesParallaxShowcase → FooterBasic. *(No navbar — deliberately bare.)*
Signature: **`HeroStickerFlip`** (playful flipping-sticker hero) · carousel marquee · **`FeaturesParallaxShowcase`**. *Parallax-forward, casual.*

## Product & retail

**`Reference21`** — light neutral, minimal, single-object focus.
Palette **light**: bg `#f1f1f1` · fg `#1A1A1A` · cta `#1A1A1A` · accent `#7A7A72`. Skin: soft radius `1.5rem` · hover *default* · text *slide-up*.
Flow: NavbarCenteredOverlay → HeroOverlayParallax → AboutParallaxHighlight → ProductVariantCardsHighlight → TestimonialDetailedCardsHighlight → FaqSimpleHighlight → FooterSimpleReveal.
Signature: **`HeroOverlayParallax`** + `AboutParallaxHighlight` (parallax product story) · "highlight" variants throughout · footer reveal. *One-product showcase.*

**`Reference22`** — cream & espresso, cozy, tactile.
Palette **light**: bg `#F5F0E8` · fg `#2C1810` · cta `#2C1810` · accent `#8B7355` (coffee). Skin: soft radius `1.75rem` · hover *bounce* · text *fade-blur* · display font **Caveat**.
Flow: NavbarFullscreen → HeroBillboardBrandFloatingCards → AboutCursorTrail → FeaturesFilterGrid → FeaturesGridSplitLarge → ContactBar → FooterBrand.
Signature: **`AboutCursorTrail`** (GSAP cursor image-trail) · floating-cards brand hero · **filterable** menu grid. *The cursor-trail showcase.*

**`Reference23`** — rose luxury, deep oxblood, sensual.
Palette **light**: bg `#f5f5f5` · fg `#1c1c1c` · cta `#511f1f` · accent `#8f3838` (oxblood). Skin: soft radius `1.5rem` · layered-gradient cards · radial-glow/glass buttons · hover *elastic* · text *fade*.
Flow: NavbarDropdown → HeroBillboardTiltedCarousel → ProductVariantCards → FeaturesAlternatingSplit → FeaturesMediaCards → BlogSimpleCards → FaqSplitMedia → ContactSplitForm → FooterBrand.
Signature: **`lightRaysCorner`** glow · **tilted 3D carousel hero** · layered-gradient cards · elastic buttons. *The richest product-luxury skin.*
