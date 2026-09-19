import { useEffect, useState } from "react";
import { ArrowUpRight } from "lucide-react";
import { cls } from "./utils";

/* Fullscreen curtain menu.

   The curtain is a clip-path polygon animated from a zero-height strip at the top
   edge to the full viewport, so it reads as a sheet dropping rather than a panel
   fading. Links live in overflow-hidden rows and slide up from 100%, staggered on
   open and stagger-REVERSED on close so they leave bottom-up instead of replaying
   the entrance backwards. That reversal is most of why it feels considered.

   The nav layer is pointer-events-none with pointer-events-auto only on the bar
   and the curtain, so the page underneath stays clickable while the menu is shut. */

const CURTAIN_CLOSED = "polygon(0% 0%, 100% 0%, 100% 0%, 0% 0%)";
const CURTAIN_OPEN = "polygon(0% 0%, 100% 0%, 100% 100%, 0% 100%)";

type NavItem = { name: string; href: string };

type NavbarFullscreenProps = {
  logo: React.ReactNode;
  navItems: NavItem[];
  /** Rendered in the bar next to the toggle — supply your own button. */
  action?: React.ReactNode;
};

const NavbarFullscreen = ({ logo, navItems, action }: NavbarFullscreenProps) => {
  const [open, setOpen] = useState(false);

  // Lock the page while the curtain is down, and let Escape out.
  useEffect(() => {
    if (!open) return;
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    window.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = previous;
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <nav className="fixed inset-0 z-50 pointer-events-none">
      <div
        className="absolute inset-0 bg-foreground transition-[clip-path] duration-700 ease-[cubic-bezier(0.9,0,0.1,1)]"
        style={{ clipPath: open ? CURTAIN_OPEN : CURTAIN_CLOSED }}
        aria-hidden={!open}
      >
        <div className="w-content-width mx-auto h-full flex flex-col justify-center pointer-events-auto">
          {navItems.map((item, i) => (
            <a
              key={item.href}
              href={item.href}
              onClick={() => setOpen(false)}
              className="group border-t border-background/20 last:border-b overflow-hidden"
            >
              <span
                className="flex items-center justify-between py-3 text-7xl md:text-9xl text-background transition-transform ease-[cubic-bezier(0.7,0,0.3,1)] duration-500"
                style={{
                  transform: open ? "translateY(0)" : "translateY(100%)",
                  // opening cascades top-down; closing runs bottom-up
                  transitionDelay: `${
                    open ? 0.3 + i * 0.05 : (navItems.length - 1 - i) * 0.05
                  }s`,
                }}
              >
                <span className="transition-all duration-300 group-hover:ml-4">
                  {item.name}
                </span>
                <ArrowUpRight
                  className="size-[0.7em] transition-transform duration-300 group-hover:rotate-45"
                  aria-hidden="true"
                />
              </span>
            </a>
          ))}
        </div>
      </div>

      <div className="relative w-content-width mx-auto flex items-center justify-between py-6 pointer-events-auto">
        <span
          className={cls(
            "text-xl font-semibold transition-colors duration-700",
            open ? "text-background" : "text-foreground"
          )}
        >
          {logo}
        </span>

        <div className="flex items-center gap-4">
          {action}
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            aria-label={open ? "Close menu" : "Open menu"}
            className="flex flex-col items-center justify-center size-10 cursor-pointer"
          >
            {[-1, 1].map((dir) => (
              <span
                key={dir}
                className={cls(
                  "w-3 h-px transition-all duration-300",
                  open ? "bg-background" : "bg-foreground"
                )}
                style={{
                  transform: open
                    ? `rotate(${dir * 45}deg)`
                    : `translateY(${dir * 0.25}rem)`,
                }}
              />
            ))}
          </button>
        </div>
      </div>
    </nav>
  );
};

export default NavbarFullscreen;
