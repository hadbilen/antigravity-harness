import { cls } from "./utils";

type NoiseBackgroundProps = {
  position: "fixed" | "absolute";
};

/* Grain is generated in-page with an SVG turbulence filter — no image request,
   no external asset. baseFrequency drives coarseness: lower = softer clouds,
   higher = finer sand. 0.8 reads as film grain at a 512px tile. */
const GRAIN =
  "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='512' height='512'%3E%3Cfilter id='g'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.8' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='512' height='512' filter='url(%23g)'/%3E%3C/svg%3E\")";

const NoiseBackground = ({ position }: NoiseBackgroundProps) => {
  return (
    <div
      className={cls(
        position,
        "inset-0 -z-10 overflow-hidden bg-background-accent/10 pointer-events-none select-none",
        position === "absolute" &&
          "mask-[linear-gradient(to_bottom,transparent,black_10%,black_90%,transparent)]"
      )}
      aria-hidden="true"
    >
      <div
        className="absolute inset-0 bg-repeat mix-blend-overlay opacity-10"
        style={{ backgroundImage: GRAIN, backgroundSize: "512px" }}
      />
    </div>
  );
};

export default NoiseBackground;
