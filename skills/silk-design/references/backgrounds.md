# Animated backgrounds — 13 of them

Ambient motion behind content. Subtle by design (opacities 5–20%) — they add life without competing.
Three are shipped in `assets/`; all 13 follow one pattern, so you can build any from the recipe.

## The shared pattern (every background)
```tsx
const Background = ({ position }: { position: "fixed" | "absolute" }) => (
  <div className={cls(position,
    "inset-0 -z-10 w-full h-full overflow-hidden bg-background pointer-events-none select-none",
    position === "absolute" &&
      "mask-[linear-gradient(to_bottom,transparent,black_10%,black_90%,transparent)]")}
    aria-hidden="true">
    {/* low-opacity token-colored layers, animated via a keyframe class */}
  </div>
);
```
- `-z-10` + `pointer-events-none` → sits behind content, never intercepts clicks.
- `position="fixed"` for a whole-page ambient; `"absolute"` to scope it to one section (the mask fades it
  in/out at the section's top/bottom so it doesn't hard-edge).
- Colors come from tokens (`bg-background-accent/15`, `bg-primary-cta`) so it recolors with the theme.
- Motion comes from the keyframes in `assets/animations.css` — no JS.

## The catalog

| background | look | how it's built | driven by |
|---|---|---|---|
| **Aurora** ✅ | soft diagonal color veils, blurred | 5 rotated `rounded-[100%]` blobs at `bg-background-accent/10–20` + `backdrop-blur-3xl` | static (or `@keyframes aurora` bg-position drift) |
| **GradientBars** ✅ | faint vertical light bars L & R | two rows of `flex-1` bars, `opacity-0.075`, `bg-[linear-gradient(90deg,var(--color-primary-cta),transparent)]`, mask-faded | static |
| **Noise** ✅ | film-grain texture | tiled `noise.webp` at `mix-blend-overlay opacity-10 bg-size-[512px]` | static |
| **NoiseGradient** | grain + a color wash | Noise layer over a radial/linear token gradient | static |
| **LightRaysCenter** | rays pulsing from center | angled thin gradient slivers rotated around center | `@keyframes ray-pulse` (opacity 0↔`--ray-opacity`) |
| **LightRaysCorner** | rays from a corner | same, anchored to a corner | `@keyframes rotated-ray-pulse` |
| **FloatingGradient** | slow-drifting color blobs | 2–3 blurred radial blobs | `floating-move-in-circle / -vertical / -horizontal` |
| **CornerGlow** | soft glow bleeding from a corner | one large blurred radial at low opacity | static / slow pulse |
| **HorizonGlow** | glowing horizon band | wide blurred gradient bar low on the section | static |
| **RadialGradient** | vignette-ish center glow | single `radial-gradient` token layer | static |
| **GridLines** | faint technical grid | repeating-linear-gradient grid at low opacity | static |
| **ColumnWave** | columns lighting up in sequence | grid of columns | `@keyframes cell-wave-pulse` (staggered opacity) |
| **Grid dots** | dotted grid | `radial-gradient` dot pattern, low opacity | static |

✅ = shipped in `assets/`. The rest: build from the pattern above + the named keyframe (all
keyframes are already in `assets/animations.css`). Aurora, Noise, and a subtle RadialGradient are the safest defaults for most sites.

## Choosing one
- Dark, techy, premium → Aurora, LightRays, GradientBars.
- Warm / editorial / product → Noise or NoiseGradient (barely-there grain reads as "print quality").
- Clean SaaS → GridLines or Grid dots + a CornerGlow.
- **One per page, low opacity.** Two competing animated backgrounds is noise, not polish.
