import { useRef, useState, useEffect } from "react";
import { motion, useMotionValue, useMotionTemplate } from "motion/react";
import { cls } from "./utils";

const CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const randomChars = () => Array.from({ length: 1500 }, () => CHARS[Math.floor(Math.random() * 62)]).join("");

interface HoverPatternProps {
  children: React.ReactNode;
  className?: string;
}

const HoverPattern = ({ children, className = "" }: HoverPatternProps) => {
  const ref = useRef<HTMLDivElement>(null);
  const x = useMotionValue(0);
  const y = useMotionValue(0);
  const [chars, setChars] = useState(randomChars);
  const [isMobile, setIsMobile] = useState(false);

  useEffect(() => {
    const checkMobile = () => setIsMobile(window.innerWidth < 768);
    checkMobile();
    window.addEventListener("resize", checkMobile);
    return () => window.removeEventListener("resize", checkMobile);
  }, []);

  useEffect(() => {
    if (isMobile && ref.current) {
      x.set(ref.current.offsetWidth / 2);
      y.set(ref.current.offsetHeight / 2);
    }
  }, [isMobile, x, y]);

  const mask = useMotionTemplate`radial-gradient(${isMobile ? 110 : 250}px at ${x}px ${y}px, white, transparent)`;
  const base = "absolute inset-0 rounded-[inherit] transition-opacity duration-300";

  return (
    <div
      ref={ref}
      className={cls("group/pattern relative", className)}
      onMouseMove={isMobile ? undefined : (e) => {
        if (!ref.current) return;
        const rect = ref.current.getBoundingClientRect();
        x.set(e.clientX - rect.left);
        y.set(e.clientY - rect.top);
        setChars(randomChars());
      }}
    >
      {children}
      <div className="pointer-events-none absolute inset-0 rounded-[inherit]">
        <div className={cls(base, isMobile ? "opacity-25" : "opacity-0 group-hover/pattern:opacity-25")} style={{ background: "linear-gradient(var(--foreground), transparent)" }} />
        <motion.div className={cls(base, "bg-linear-to-r from-accent to-accent/50 backdrop-blur-xl", isMobile ? "opacity-100" : "opacity-0 group-hover/pattern:opacity-100")} style={{ maskImage: mask, WebkitMaskImage: mask }} />
        <motion.div className={cls(base, "mix-blend-overlay", isMobile ? "opacity-100" : "opacity-0 group-hover/pattern:opacity-100")} style={{ maskImage: mask, WebkitMaskImage: mask }}>
          <p className="absolute inset-0 h-full whitespace-pre-wrap wrap-break-word font-mono text-xs font-bold text-foreground">{chars}</p>
        </motion.div>
      </div>
    </div>
  );
};

export default HoverPattern;
