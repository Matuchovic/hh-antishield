// Skleněné ilustrace pro dlaždice na přehledu (dekorace).

export type TileArtKind = "folder" | "lock" | "wrench";

function Defs({ id }: { id: string }) {
  return (
    <defs>
      <linearGradient id={`${id}-a`} x1="0" y1="0" x2="0" y2="1">
        <stop offset="0" stopColor="#8cc4ff" />
        <stop offset="1" stopColor="#1f5fe0" />
      </linearGradient>
      <linearGradient id={`${id}-b`} x1="0" y1="0" x2="1" y2="1">
        <stop offset="0" stopColor="#4d9bff" stopOpacity="0.95" />
        <stop offset="1" stopColor="#0d3aa0" stopOpacity="0.9" />
      </linearGradient>
      <radialGradient id={`${id}-g`} cx="0.5" cy="0.5" r="0.5">
        <stop offset="0" stopColor="#3d8bff" stopOpacity="0.55" />
        <stop offset="1" stopColor="#3d8bff" stopOpacity="0" />
      </radialGradient>
    </defs>
  );
}

export function TileArt({ kind }: { kind: TileArtKind }) {
  const id = `art-${kind}`;
  return (
    <svg className="tile-art" viewBox="0 0 160 110" aria-hidden="true">
      <Defs id={id} />
      <ellipse cx="80" cy="96" rx="62" ry="12" fill={`url(#${id}-g)`} />
      {kind === "folder" ? (
        <g>
          <path d="M34 26h30l8 9h52a6 6 0 0 1 6 6v46a6 6 0 0 1-6 6H34a6 6 0 0 1-6-6V32a6 6 0 0 1 6-6z" fill={`url(#${id}-a)`} opacity="0.55" />
          <path d="M26 44h108l-8 46a6 6 0 0 1-6 5H36a6 6 0 0 1-6-5z" fill={`url(#${id}-b)`} stroke="#b9dcff" strokeOpacity="0.7" />
          <path d="M34 50h92" stroke="#e3f1ff" strokeOpacity="0.6" strokeWidth="2" strokeLinecap="round" />
        </g>
      ) : null}
      {kind === "lock" ? (
        <g>
          <path d="M58 48V36a22 22 0 0 1 44 0v12" fill="none" stroke={`url(#${id}-a)`} strokeWidth="9" strokeLinecap="round" />
          <rect x="44" y="46" width="72" height="50" rx="10" fill={`url(#${id}-b)`} stroke="#b9dcff" strokeOpacity="0.7" />
          <circle cx="80" cy="66" r="7" fill="#e3f1ff" />
          <path d="M80 70v12" stroke="#e3f1ff" strokeWidth="5" strokeLinecap="round" />
        </g>
      ) : null}
      {kind === "wrench" ? (
        <g transform="rotate(-38 80 58)">
          <path
            d="M70 14a22 22 0 0 0 0 40v44a10 10 0 0 0 20 0V54a22 22 0 0 0 0-40v18l-10 7-10-7z"
            fill={`url(#${id}-b)`}
            stroke="#b9dcff"
            strokeOpacity="0.7"
          />
          <path d="M80 62v32" stroke="#e3f1ff" strokeOpacity="0.55" strokeWidth="3" strokeLinecap="round" />
        </g>
      ) : null}
    </svg>
  );
}
