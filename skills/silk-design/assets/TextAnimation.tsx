import { useState, useEffect } from "react";
import { motion } from "motion/react";
import { cls } from "./utils";

type Variant = "slide-up" | "fade-blur" | "fade";

interface TextAnimationProps {
  text: string;
  variant: Variant;
  gradientText: boolean;
  tag?: "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "p" | "span" | "div";
  className?: string;
}

const VARIANTS = {
  "slide-up": {
    hidden: { opacity: 0, y: "50%" },
    visible: { opacity: 1, y: 0 },
  },
  "fade-blur": {
    hidden: { opacity: 0, filter: "blur(10px)" },
    visible: { opacity: 1, filter: "none" },
  },
  "fade": {
    hidden: { opacity: 0 },
    visible: { opacity: 1 },
  },
};

const EASING: Record<Variant, [number, number, number, number]> = {
  "slide-up": [0.25, 0.46, 0.45, 0.94],
  "fade-blur": [0.45, 0, 0.55, 1],
  "fade": [0.45, 0, 0.55, 1],
};

const TextAnimation = ({ text, variant, gradientText, tag = "p", className = "" }: TextAnimationProps) => {
  const Tag = motion[tag] as typeof motion.p;
  const words = text.split(" ");
  const [animationComplete, setAnimationComplete] = useState(false);
  const [reverted, setReverted] = useState(false);

  const gradientClass = gradientText
    ? "bg-gradient-to-r from-foreground to-primary-cta bg-clip-text text-transparent pb-[0.1em] -mb-[0.1em]"
    : "";

  useEffect(() => {
    if (animationComplete && !reverted) {
      const delay = variant === "fade-blur" && gradientText ? 0 : 700;
      const timer = setTimeout(() => {
        setReverted(true);
      }, delay);
      return () => clearTimeout(timer);
    }
  }, [animationComplete, reverted, variant, gradientText]);

  if (reverted) {
    return (
      <Tag
        className={cls("leading-[1.2]", gradientClass, className)}
        initial={false}
      >
        {text}
      </Tag>
    );
  }

  return (
    <Tag
      className={cls(
        "leading-[1.2] transition-all duration-700",
        animationComplete && gradientClass,
        className
      )}
      initial="hidden"
      whileInView="visible"
      viewport={{ once: true, margin: "-20%" }}
      transition={{ staggerChildren: 0.04 }}
      onAnimationComplete={() => setAnimationComplete(true)}
    >
      {words.map((word, i) => (
        <span key={i}>
          {i > 0 && " "}
          <motion.span
            className="inline-block"
            variants={VARIANTS[variant]}
            transition={{ duration: 0.6, ease: EASING[variant] }}
          >
            {word}
          </motion.span>
        </span>
      ))}
    </Tag>
  );
};

export default TextAnimation;
