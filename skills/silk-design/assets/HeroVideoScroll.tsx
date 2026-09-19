import { useEffect, useRef, useState } from "react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { motion } from "motion/react";
import { cls } from "./utils";

gsap.registerPlugin(ScrollTrigger);

/* Scroll-scrubbed video hero.

   A 300vh spacer gives the scrub its runway; the visible frame is sticky inside
   it, so the page scrolls but the hero holds. ScrollTrigger maps progress onto
   video.currentTime instead of playing the video, which is what makes it feel
   like a controlled camera rather than an autoplaying clip. scrub: 0.5 adds just
   enough lag that the frames glide instead of snapping.

   Seeking before metadata exists silently does nothing, so the trigger is wired
   only after canplaythrough — with an 8s fallback so a slow or blocked network
   degrades to a static poster rather than an empty hero. */

const RUNWAY = 3;        // viewport heights of scroll the scrub spans
const SCRUB = 0.5;       // seconds of catch-up lag
const READY_TIMEOUT = 8000;
const EASE_OUT_QUINT = [0.22, 1, 0.36, 1] as const;

type HeroVideoScrollProps = {
  videoSrc: string;
  /** Shown while the video buffers, and if it never arrives. */
  posterSrc?: string;
  title: string;
  description?: string;
  actions?: React.ReactNode;
  className?: string;
};

const HeroVideoScroll = ({
  videoSrc,
  posterSrc,
  title,
  description,
  actions,
  className,
}: HeroVideoScrollProps) => {
  const sectionRef = useRef<HTMLElement>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const [ready, setReady] = useState(false);

  // Wait for enough buffer that seeking actually lands on a frame.
  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;
    if (video.readyState >= 4) {
      setReady(true);
      return;
    }
    const onReady = () => setReady(true);
    video.addEventListener("canplaythrough", onReady, { once: true });
    const fallback = window.setTimeout(onReady, READY_TIMEOUT);
    return () => {
      video.removeEventListener("canplaythrough", onReady);
      window.clearTimeout(fallback);
    };
  }, []);

  useEffect(() => {
    const section = sectionRef.current;
    const video = videoRef.current;
    if (!ready || !section || !video) return;

    const trigger = ScrollTrigger.create({
      trigger: section,
      start: "top top",
      end: "bottom bottom",
      scrub: SCRUB,
      onUpdate: (self) => {
        const duration = video.duration;
        if (Number.isFinite(duration)) video.currentTime = duration * self.progress;
      },
    });

    return () => trigger.kill();
  }, [ready]);

  return (
    <section
      ref={sectionRef}
      data-section="hero"
      className={cls("relative w-full", className)}
      style={{ height: `${RUNWAY * 100}vh` }}
    >
      <div className="sticky top-0 h-svh w-full overflow-hidden">
        <video
          ref={videoRef}
          src={videoSrc}
          poster={posterSrc}
          muted
          playsInline
          preload="auto"
          aria-hidden="true"
          className={cls(
            "absolute inset-0 size-full object-cover transition-opacity duration-500",
            ready ? "opacity-100" : "opacity-0"
          )}
        />

        {/* Clip-path wipe: the frame opens from a centre band rather than fading,
            which hides the moment the first video frame pops in. */}
        <motion.div
          initial={{ clipPath: "inset(45% 0% 45% 0%)" }}
          animate={ready ? { clipPath: "inset(0% 0% 0% 0%)" } : undefined}
          transition={{ duration: 1.1, ease: EASE_OUT_QUINT }}
          className="absolute inset-0 bg-background/20"
          aria-hidden="true"
        />

        <div className="relative z-10 h-full w-content-width mx-auto flex flex-col justify-end pb-24 text-background">
          <motion.h1
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.2, ease: EASE_OUT_QUINT }}
            className="text-6xl md:text-9xl font-medium text-balance"
          >
            {title}
          </motion.h1>

          {description ? (
            <motion.p
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.4, ease: EASE_OUT_QUINT }}
              className="mt-6 max-w-xl text-lg opacity-80"
            >
              {description}
            </motion.p>
          ) : null}

          {actions ? (
            <motion.div
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.4, ease: EASE_OUT_QUINT }}
              className="mt-10 flex flex-wrap gap-4"
            >
              {actions}
            </motion.div>
          ) : null}
        </div>
      </div>
    </section>
  );
};

export default HeroVideoScroll;
