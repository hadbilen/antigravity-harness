import { useRef, useEffect, useState } from "react";
import { cls } from "./utils";

const AutoFillText = ({
  children,
  className = "",
  paddingY = "py-10",
}: {
  children: string;
  className?: string;
  paddingY?: string;
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const textRef = useRef<HTMLHeadingElement>(null);
  const [fontSize, setFontSize] = useState<number | null>(null);

  const hasDescenders = /[gjpqy]/.test(children);
  const lineHeight = hasDescenders ? 1.2 : 0.8;

  useEffect(() => {
    const container = containerRef.current;
    const text = textRef.current;
    if (!container || !text) return;

    const calculateSize = () => {
      const containerWidth = container.offsetWidth;
      if (containerWidth === 0) return;

      const canvas = document.createElement("canvas");
      const ctx = canvas.getContext("2d");
      if (!ctx) return;

      const styles = getComputedStyle(text);
      ctx.font = `${styles.fontWeight} 100px ${styles.fontFamily}`;
      const textWidth = ctx.measureText(children).width;

      if (textWidth > 0) {
        setFontSize((containerWidth / textWidth) * 100);
      }
    };

    calculateSize();

    const observer = new ResizeObserver(calculateSize);
    observer.observe(container);

    return () => observer.disconnect();
  }, [children]);

  return (
    <div ref={containerRef} className={cls("w-full min-w-0 flex-1", !hasDescenders && paddingY)}>
      <h2
        ref={textRef}
        className={cls(
          "whitespace-nowrap transition-opacity duration-150",
          fontSize ? "opacity-100" : "opacity-0",
          className
        )}
        style={{ fontSize: fontSize ? `${fontSize}px` : undefined, lineHeight }}
      >
        {children}
      </h2>
    </div>
  );
};

export default AutoFillText;
