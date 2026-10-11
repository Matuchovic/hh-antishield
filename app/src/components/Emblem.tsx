import logo from "../assets/hh-logo.png";
import { SHIELD_LAYERS, stateTone } from "../lib/format";
import type { ComponentStatus } from "../lib/types";

// Znak s logem. Vnější prstenec má 6 oblouků, jeden za každou ochrannou
// vrstvu: svítí jen ty, které engine hlásí jako běžící.

const C = 150;
const R = 138;

function arc(index: number): string {
  const gap = 8;
  const start = -90 + index * 60 + gap / 2;
  const end = start + 60 - gap;
  const point = (deg: number) => {
    const rad = (deg * Math.PI) / 180;
    return `${(C + R * Math.cos(rad)).toFixed(2)} ${(C + R * Math.sin(rad)).toFixed(2)}`;
  };
  return `M ${point(start)} A ${R} ${R} 0 0 1 ${point(end)}`;
}

const TICKS = Array.from({ length: 72 }, (_, i) => i * 5);

export function Emblem({ components, scanning }: { components: ComponentStatus[]; scanning: boolean }) {
  const layers = SHIELD_LAYERS.map((kind) => {
    const state = components.find((c) => c.kind === kind)?.state;
    return state ? stateTone(state) : "off";
  });
  const running = layers.filter((t) => t === "good").length;

  return (
    <figure className="emblem-wrap">
      <div
        className={`emblem${scanning ? " is-scanning" : ""}`}
        role="img"
        aria-label={`${running} ze ${SHIELD_LAYERS.length} ochranných vrstev běží`}
      >
        <div className="emblem-halo" />
        <div className="emblem-sweep" />
        <svg className="emblem-rings" viewBox="0 0 300 300" aria-hidden="true">
          <defs>
            <filter id="em-glow" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="3.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          <g className="ring-spin slow">
            <circle cx={C} cy={C} r="149" className="ring-dash" />
          </g>
          {layers.map((tone, i) => (
            <path key={SHIELD_LAYERS[i]} d={arc(i)} pathLength={1} className={`layer-arc tone-${tone} a${i}`} filter={tone === "good" ? "url(#em-glow)" : undefined} />
          ))}
          <g className="ring-spin reverse">
            {TICKS.map((deg) => (
              <line
                key={deg}
                x1={C}
                y1={C - 122}
                x2={C}
                y2={C - (deg % 30 === 0 ? 114 : 118)}
                transform={`rotate(${deg} ${C} ${C})`}
                className="tick"
              />
            ))}
          </g>
          <circle cx={C} cy={C} r="106" className="ring-thin" />
        </svg>
        <div className="emblem-logo">
          <img src={logo} alt="" draggable={false} />
          <span className="logo-shine" />
        </div>
      </div>
      <figcaption className="emblem-caption">
        <strong>{running}</strong> ze {SHIELD_LAYERS.length} vrstev běží
      </figcaption>
    </figure>
  );
}
