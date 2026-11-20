import { cloneElement, useEffect, useId, useRef, useState } from "react";
import type { ReactElement } from "react";
import { createPortal } from "react-dom";

export function NavigationHint({ description, children }: {
  description: string;
  children: ReactElement<{ "aria-describedby"?: string }>;
}) {
  const id = useId();
  const anchor = useRef<HTMLDivElement>(null);
  const [position, setPosition] = useState<{ top: number; left: number }>();
  const close = () => setPosition(undefined);
  const show = () => {
    window.dispatchEvent(new CustomEvent("navigation-hint-open", { detail: id }));
    const rect = anchor.current?.getBoundingClientRect();
    if (rect) setPosition({ top: Math.max(8, Math.min(rect.top, innerHeight - 100)),
      left: Math.max(8, Math.min(rect.right + 12, innerWidth - 280)) });
  };
  useEffect(() => {
    const closeOther = (event: Event) => { if ((event as CustomEvent<string>).detail !== id) close(); };
    window.addEventListener("navigation-hint-open", closeOther);
    return () => window.removeEventListener("navigation-hint-open", closeOther);
  }, [id]);
  useEffect(() => {
    if (!position) return;
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    return () => { window.removeEventListener("scroll", close, true); window.removeEventListener("resize", close); };
  }, [position]);
  return <div ref={anchor} className="navigation-hint-anchor" onMouseEnter={show} onMouseLeave={close}
    onFocus={show} onBlur={close} onKeyDown={event => { if (event.key === "Escape") close(); }}>
    {cloneElement(children, { "aria-describedby": position ? id : undefined })}
    {position && createPortal(<div id={id} role="tooltip" className="navigation-hint" style={position}>{description}</div>, document.body)}
  </div>;
}
