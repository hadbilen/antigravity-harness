import { cls } from "./utils";

type GradientBarsBackgroundProps = {
  position: "fixed" | "absolute";
};

const GradientBarsBackground = ({ position }: GradientBarsBackgroundProps) => {
  return (
    <div className={cls(position, "inset-0 -z-10 overflow-hidden pointer-events-none select-none")} aria-hidden="true">
      <div className="flex h-4/5 w-full justify-between mask-[linear-gradient(0deg,transparent_0%,black_100%)]">
        <div className="flex h-full w-[35%] overflow-hidden mask-[linear-gradient(270deg,transparent_0%,black_100%)]">
          <div className="h-full flex-1 min-w-[30px] max-w-[82px] opacity-[0.075] bg-[linear-gradient(90deg,var(--color-primary-cta),transparent)]" />
          <div className="h-full flex-1 min-w-[30px] max-w-[82px] opacity-[0.075] bg-[linear-gradient(90deg,var(--color-primary-cta),transparent)]" />
          <div className="h-full flex-1 min-w-[30px] max-w-[82px] opacity-[0.075] bg-[linear-gradient(90deg,var(--color-primary-cta),transparent)]" />
          <div className="h-full flex-1 min-w-[30px] max-w-[82px] opacity-[0.075] bg-[linear-gradient(90deg,var(--color-primary-cta),transparent)]" />
          <div className="h-full flex-1 min-w-[30px] max-w-[82px] opacity-[0.075] bg-[linear-gradient(90deg,var(--color-primary-cta),transparent)]" />
          <div className="h-full flex-1 min-w-[30px] max-w-[82px] opacity-[0.075] bg-[linear-gradient(90deg,var(--color-primary-cta),transparent)]" />
          <div className="h-full flex-1 min-w-[30px] max-w-[82px] opacity-[0.075] bg-[linear-gradient(90deg,var(--color-primary-cta),transparent)]" />
          <div className="h-full flex-1 min-w-[30px] max-w-[82px] opacity-[0.075] bg-[linear-gradient(90deg,var(--color-primary-cta),transparent)]" />
        </div>

        <div className="flex h-full w-[35%] justify-end overflow-hidden mask-[linear-gradient(90deg,transparent_0%,black_100%)]">
          <div className="h-full flex-1 min-w-[30px] max-w-[82px] opacity-[0.075] bg-[linear-gradient(270deg,var(--color-primary-cta),transparent)]" />
          <div className="h-full flex-1 min-w-[30px] max-w-[82px] opacity-[0.075] bg-[linear-gradient(270deg,var(--color-primary-cta),transparent)]" />
          <div className="h-full flex-1 min-w-[30px] max-w-[82px] opacity-[0.075] bg-[linear-gradient(270deg,var(--color-primary-cta),transparent)]" />
          <div className="h-full flex-1 min-w-[30px] max-w-[82px] opacity-[0.075] bg-[linear-gradient(270deg,var(--color-primary-cta),transparent)]" />
          <div className="h-full flex-1 min-w-[30px] max-w-[82px] opacity-[0.075] bg-[linear-gradient(270deg,var(--color-primary-cta),transparent)]" />
          <div className="h-full flex-1 min-w-[30px] max-w-[82px] opacity-[0.075] bg-[linear-gradient(270deg,var(--color-primary-cta),transparent)]" />
          <div className="h-full flex-1 min-w-[30px] max-w-[82px] opacity-[0.075] bg-[linear-gradient(270deg,var(--color-primary-cta),transparent)]" />
          <div className="h-full flex-1 min-w-[30px] max-w-[82px] opacity-[0.075] bg-[linear-gradient(270deg,var(--color-primary-cta),transparent)]" />
        </div>
      </div>
    </div>
  );
};

export default GradientBarsBackground;
