import { useEffect, useRef, useState } from "react";
import AutoFillText from "./AutoFillText";
import { cls } from "./utils";

/* Footer reveal-from-behind.

   No scroll listeners and no math: the outer section carries a full-rect clip-path,
   which establishes a clipping context, and the real footer inside is position:fixed
   at the bottom. The fixed child can only paint where the section allows, so the
   footer appears to sit *under* the page and get uncovered as content slides off it.

   The one moving part is height — the section has to reserve exactly as much space
   as the fixed footer occupies, or the page ends too early or too late. A
   ResizeObserver keeps the two in step through font loads and reflows. */

const CLIP_CONTEXT = "polygon(0% 0%, 100% 0%, 100% 100%, 0% 100%)";

type FooterBrandRevealProps = {
  /** Rendered as an oversized wordmark, auto-fitted to the full content width. */
  brand: string;
  /** Each array is one column of links. */
  columns?: React.ReactNode[];
  className?: string;
};

const FooterBrandReveal = ({ brand, columns = [], className }: FooterBrandRevealProps) => {
  const footerRef = useRef<HTMLElement>(null);
  const [height, setHeight] = useState<number | null>(null);

  useEffect(() => {
    const footer = footerRef.current;
    if (!footer) return;
    const sync = () => setHeight(footer.offsetHeight);
    sync();
    const observer = new ResizeObserver(sync);
    observer.observe(footer);
    return () => observer.disconnect();
  }, []);

  const reserved = height ? `${height}px` : "auto";

  return (
    <section
      className={cls("relative z-0 w-full mt-20", className)}
      style={{ height: reserved, clipPath: CLIP_CONTEXT }}
    >
      <div className="fixed bottom-0 w-full" style={{ height: reserved }}>
        <footer
          ref={footerRef}
          data-section="footer"
          aria-label="Site footer"
          className="w-full py-16 rounded-t-lg overflow-hidden primary-button text-primary-cta-text"
        >
          <div className="w-content-width mx-auto flex flex-col gap-10 md:gap-20">
            <AutoFillText className="font-semibold">{brand}</AutoFillText>

            {columns.length ? (
              <div
                className={cls(
                  "flex flex-col gap-8 mb-10 md:flex-row",
                  columns.length === 1 ? "md:justify-center" : "md:justify-between"
                )}
              >
                {columns.map((column, i) => (
                  <div key={i} className="flex flex-col items-start gap-3">
                    {column}
                  </div>
                ))}
              </div>
            ) : null}
          </div>
        </footer>
      </div>
    </section>
  );
};

export default FooterBrandReveal;
