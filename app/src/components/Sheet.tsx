import { type KeyboardEvent, type ReactNode, useEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { Icon } from "./Icon";

/**
 * Dialog přes obrazovku: Esc a klik vedle ho zavřou, Tab zůstává uvnitř.
 * Vykreslí se do <body>, aby ho neovlivnily transformace obrazovky.
 */
export function Sheet({
  labelledBy,
  className,
  onClose,
  closeLabel,
  children,
}: {
  labelledBy: string;
  className?: string;
  onClose: () => void;
  closeLabel: string;
  children: ReactNode;
}) {
  const ref = useRef<HTMLElement>(null);

  const close = useRef(onClose);
  close.current = onClose;

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    (ref.current?.querySelector<HTMLElement>("input") ?? ref.current?.querySelector<HTMLElement>("button"))?.focus();
    // Esc zavře dialog, i když fokus zmizel (tlačítko se právě vypnulo).
    const onEscape = (e: globalThis.KeyboardEvent) => {
      if (e.key !== "Escape") return;
      e.preventDefault();
      close.current();
    };
    document.addEventListener("keydown", onEscape);
    return () => {
      document.removeEventListener("keydown", onEscape);
      previous?.focus?.();
    };
  }, []);

  const onKeyDown = (e: KeyboardEvent<HTMLElement>) => {
    if (e.key !== "Tab") return;
    const items = Array.from(
      e.currentTarget.querySelectorAll<HTMLElement>("button:not(:disabled), input:not(:disabled), [tabindex='0']"),
    );
    const first = items[0];
    const last = items[items.length - 1];
    if (!first || !last) return;
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  };

  return createPortal(
    <div className="story-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <section
        ref={ref}
        className={`story-sheet sheet${className ? ` ${className}` : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy}
        onKeyDown={onKeyDown}
      >
        <button type="button" className="story-close sheet-close" onClick={onClose} aria-label={closeLabel}>
          <Icon name="close" size={18} />
        </button>
        {children}
      </section>
    </div>,
    document.body,
  );
}
