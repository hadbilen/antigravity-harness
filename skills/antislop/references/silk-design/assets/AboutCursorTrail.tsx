import { useEffect, useRef } from "react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { cls } from "./utils";

gsap.registerPlugin(ScrollTrigger);

/* Cursor image-trail — the "move your cursor" moment.

   A fixed pool of images is recycled round-robin. A new one is dropped only once
   the pointer has travelled further than a distance threshold, so the trail is
   spaced by movement rather than by time — fast flicks scatter, slow drags dribble.
   The threshold scales with viewport width (1/15th) so it feels the same on a
   laptop and a 5K display.

   Every drop restarts an idle timer; when the pointer rests, the whole trail
   fades and shrinks away on expo.out. ScrollTrigger gates the listeners so
   nothing runs while the section is off screen, and matchMedia gives touch
   devices a scroll-driven fallback instead of a dead feature. */

const DIVISOR = 15;      // threshold = innerWidth / DIVISOR
const IDLE_MS = 350;     // rest before the trail starts clearing

type AboutCursorTrailProps = {
  tag?: string;
  title: string;
  /** Image URLs recycled as the trail. 6-10 reads best. */
  images: string[];
  actions?: React.ReactNode;
  className?: string;
};

const AboutCursorTrail = ({ tag, title, images, actions, className }: AboutCursorTrailProps) => {
  const scope = useRef<HTMLElement>(null);

  useEffect(() => {
    const root = scope.current;
    if (!root) return;

    const mm = gsap.matchMedia();

    mm.add("(hover: hover) and (pointer: fine)", () => {
      const pool = gsap.utils.toArray<HTMLElement>("[data-trail-item]", root);
      if (!pool.length) return;

      let index = 0;
      let zIndex = 1;
      let lastX = 0;
      let lastY = 0;
      let primed = false;
      let idle: number;

      const clear = () =>
        gsap.to(pool, {
          autoAlpha: 0,
          scale: 0.2,
          duration: 0.8,
          ease: "expo.out",
          overwrite: true,
        });

      const drop = (x: number, y: number) => {
        const img = pool[index % pool.length];
        index += 1;
        gsap.set(img, { x, y, zIndex: zIndex++, force3D: true, xPercent: -50, yPercent: -50 });
        gsap.fromTo(
          img,
          { autoAlpha: 0, scale: 0.8 },
          { autoAlpha: 1, scale: 1, duration: 0.2, overwrite: true }
        );
      };

      const onMove = (e: PointerEvent) => {
        const rect = root.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;

        if (!primed) {
          lastX = x;
          lastY = y;
          primed = true;
        }

        if (Math.hypot(x - lastX, y - lastY) > window.innerWidth / DIVISOR) {
          lastX = x;
          lastY = y;
          drop(x, y);
        }

        window.clearTimeout(idle);
        idle = window.setTimeout(clear, IDLE_MS);
      };

      // Only listen while the section is actually on screen.
      const gate = ScrollTrigger.create({
        trigger: root,
        start: "top bottom",
        end: "bottom top",
        onEnter: () => root.addEventListener("pointermove", onMove),
        onEnterBack: () => root.addEventListener("pointermove", onMove),
        onLeave: () => {
          root.removeEventListener("pointermove", onMove);
          clear();
        },
        onLeaveBack: () => {
          root.removeEventListener("pointermove", onMove);
          clear();
        },
      });

      return () => {
        window.clearTimeout(idle);
        root.removeEventListener("pointermove", onMove);
        gate.kill();
      };
    });

    return () => mm.revert();
  }, [images.length]);

  return (
    <section
      ref={scope}
      data-section="about"
      className={cls(
        "relative w-full min-h-svh overflow-hidden flex flex-col items-center justify-center text-center",
        className
      )}
    >
      {/* trail layer — inert, purely decorative */}
      <div className="absolute inset-0 pointer-events-none" aria-hidden="true">
        {images.map((src, i) => (
          <img
            key={`${src}-${i}`}
            data-trail-item
            src={src}
            alt=""
            loading="lazy"
            className="absolute top-0 left-0 w-[18vw] max-w-64 aspect-[3/4] object-cover rounded-md opacity-0 will-change-transform"
          />
        ))}
      </div>

      <div className="relative z-10 w-content-width mx-auto pointer-events-none">
        {tag ? <p className="text-sm uppercase tracking-widest opacity-60 mb-6">{tag}</p> : null}
        <h2 className="text-5xl md:text-8xl font-medium text-balance">{title}</h2>
        {actions ? (
          <div className="mt-10 flex flex-wrap gap-4 justify-center pointer-events-auto">{actions}</div>
        ) : null}
      </div>
    </section>
  );
};

export default AboutCursorTrail;
