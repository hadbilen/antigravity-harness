"use client";

import { useEffect, useRef } from "react";
import { cls } from "./utils";
import { animate } from "motion/react";

const spread = 40;
const proximity = 64;
const borderWidth = 1.5;

const BorderGlow = ({ className }: { className?: string }) => {
  const ref = useRef<HTMLDivElement>(null);
  const rafRef = useRef<number>(0);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    const onPointerMove = (e: PointerEvent) => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);

      rafRef.current = requestAnimationFrame(() => {
        const { left, top, width, height } = el.getBoundingClientRect();
        const { clientX: x, clientY: y } = e;

        const isActive =
          x > left - proximity &&
          x < left + width + proximity &&
          y > top - proximity &&
          y < top + height + proximity;

        el.style.setProperty("--active", isActive ? "1" : "0");
        if (!isActive) return;

        const centerX = left + width / 2;
        const centerY = top + height / 2;
        const currentAngle = parseFloat(el.style.getPropertyValue("--start")) || 0;
        const targetAngle = (Math.atan2(y - centerY, x - centerX) * 180) / Math.PI + 90;
        const angleDiff = ((targetAngle - currentAngle + 180) % 360) - 180;

        animate(currentAngle, currentAngle + angleDiff, {
          duration: 2,
          ease: [0.16, 1, 0.3, 1],
          onUpdate: (v) => el.style.setProperty("--start", String(v)),
        });
      });
    };

    document.body.addEventListener("pointermove", onPointerMove, { passive: true });
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
      document.body.removeEventListener("pointermove", onPointerMove);
    };
  }, []);

  const gradient = `radial-gradient(circle, var(--color-accent) 10%, transparent 20%),
    radial-gradient(circle at 40% 40%, var(--color-background-accent) 5%, transparent 15%),
    repeating-conic-gradient(from 236.84deg at 50% 50%, var(--color-accent) 0%, var(--color-background-accent) 5%, var(--color-accent) 10%)`;

  return (
    <div
      ref={ref}
      style={{ "--spread": spread, "--start": 0, "--active": 0, "--border-width": `${borderWidth}px`, "--gradient": gradient } as React.CSSProperties}
      className={cls("pointer-events-none absolute inset-0 rounded-[inherit]", className)}
    >
      <div
        className={cls(
          "rounded-[inherit]",
          'after:content-[""] after:rounded-[inherit] after:absolute after:inset-[calc(-1*var(--border-width))]',
          "after:[border:var(--border-width)_solid_transparent]",
          "after:[background:var(--gradient)] after:bg-fixed",
          "after:opacity-(--active) after:transition-opacity after:duration-300",
          "after:[mask-clip:padding-box,border-box] after:mask-intersect",
          "after:mask-[linear-gradient(#0000,#0000),conic-gradient(from_calc((var(--start)-var(--spread))*1deg),#00000000_0deg,#fff,#00000000_calc(var(--spread)*2deg))]"
        )}
      />
    </div>
  );
};

export default BorderGlow;
