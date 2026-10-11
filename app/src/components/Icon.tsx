import type { ReactNode } from "react";

// Čárové ikony 24×24, barva z currentColor.
const PATHS = {
  home: <path d="M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z" />,
  search: (
    <>
      <circle cx="11" cy="11" r="7" />
      <path d="m20 20-4.2-4.2" />
    </>
  ),
  results: <path d="m4 6 1.5 1.5L8 5m-4 7 1.5 1.5L8 11m-4 7 1.5 1.5L8 17m3-11h9m-9 6h9m-9 6h9" />,
  clock: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </>
  ),
  shield: <path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6zm-3 9 2 2 4-4" />,
  box: <path d="M4 8l8-4 8 4v8l-8 4-8-4zm0 0 8 4 8-4m-8 4v8" />,
  gauge: <path d="M4 18a8 8 0 1 1 16 0m-8 0 4-6" />,
  info: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v6m0-9.5v.5" />
    </>
  ),
  calendar: (
    <>
      <rect x="3" y="5" width="18" height="16" rx="2" />
      <path d="M3 10h18M8 3v4m8-4v4" />
    </>
  ),
  chart: <path d="M5 20v-9m5 9V5m5 15v-7m5 7v-3" />,
  globe: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3a14 14 0 0 1 0 18m0-18a14 14 0 0 0 0 18" />
    </>
  ),
  mail: (
    <>
      <rect x="3" y="5" width="18" height="14" rx="2" />
      <path d="m3 7 9 6 9-6" />
    </>
  ),
  lock: (
    <>
      <rect x="5" y="11" width="14" height="10" rx="2" />
      <path d="M8 11V8a4 4 0 0 1 8 0v3" />
    </>
  ),
  chevron: <path d="m9 6 6 6-6 6" />,
  check: <path d="m5 12.5 4.5 4.5L19 7.5" />,
  download: <path d="M12 4v11m0 0-4.5-4.5M12 15l4.5-4.5M5 19h14" />,
  engine: <path d="M7 7h10v10H7zm3-4v4m4-4v4m-4 10v4m4-4v4M3 10h4m-4 4h4m10-4h4m-4 4h4" />,
  key: (
    <>
      <circle cx="8" cy="15" r="4" />
      <path d="m11 12 9-9m-3 3 3 3" />
    </>
  ),
  doc: <path d="M6 3h9l4 4v14H6zm8 0v5h5M9 13h7m-7 4h7" />,
  sliders: (
    <>
      <path d="M4 6h9m4 0h3M4 12h3m4 0h9M4 18h11m4 0h1" />
      <circle cx="15" cy="6" r="2" />
      <circle cx="9" cy="12" r="2" />
      <circle cx="17" cy="18" r="2" />
    </>
  ),
  bolt: <path d="M13 3 5 14h6l-1 7 8-11h-6z" />,
  folder: <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />,
  trash: <path d="M4 7h16M9 7V4h6v3m-8 0 1 13h8l1-13" />,
  restore: <path d="M4 12a8 8 0 1 0 2.3-5.6M4 4v4h4" />,
  warning: <path d="M12 4 2.5 20h19zm0 6v4m0 3v.5" />,
  play: <path d="M8 5.5v13l10.5-6.5z" />,
  close: <path d="M6 6l12 12M18 6L6 18" />,
  power: (
    <>
      <path d="M12 3v8" />
      <path d="M6.4 6.6a8 8 0 1 0 11.2 0" />
    </>
  ),
  drive: (
    <>
      <rect x="3" y="7" width="18" height="10" rx="2" />
      <path d="M7 12h.01M11 12h6" />
    </>
  ),
  sparkle: <path d="M12 3v4m0 10v4M3 12h4m10 0h4M6 6l2.5 2.5m7 7L18 18M6 18l2.5-2.5m7-7L18 6" />,
} satisfies Record<string, ReactNode>;

export type IconName = keyof typeof PATHS;

export function Icon({ name, size = 20, className }: { name: IconName; size?: number; className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      {PATHS[name]}
    </svg>
  );
}
