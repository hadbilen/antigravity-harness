import { useRef, useEffect } from "react";
import gsap from "gsap";
import { DrawSVGPlugin } from "gsap/DrawSVGPlugin";

gsap.registerPlugin(DrawSVGPlugin);

const PageTransitionSwirl = () => {
  const wrapRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const wrap = wrapRef.current;
    if (!wrap) return;

    const path = wrap.querySelector("svg path");
    if (!path) return;

    const tl = gsap.timeline();

    tl.set(path, { strokeWidth: "35%", drawSVG: "0% 100%" });

    tl.to(path, {
      duration: 1.25,
      drawSVG: "100% 100%",
      strokeWidth: "5%",
      ease: "power1.inOut",
      delay: 0.3,
    });

    return () => {
      tl.kill();
    };
  }, []);

  return (
    <div ref={wrapRef} className="fixed inset-0 z-50 pointer-events-none overflow-clip" aria-hidden="true">
      <div className="absolute inset-0 text-primary-cta">
        <svg
          xmlns="http://www.w3.org/2000/svg"
          width="100%"
          viewBox="0 0 1000 1000"
          fill="none"
          preserveAspectRatio="none"
          className="absolute w-[130%] h-[130%] -top-[15%] -left-[15%]"
        >
          <path
            d="M43 259C296 11.5688 994 -3 922.994 498.259C851.988 999.517 281.229 1004.28 123 767C-35.2287 529.721 179 259 472 259C765 259 792 498.259 659 654C526 809.741 319 755 285 669.001C251 583.001 299 452 496 452C693 452 876.073 639.171 935 937.001"
            stroke="currentColor"
            strokeWidth="0"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </div>
    </div>
  );
};

export default PageTransitionSwirl;
