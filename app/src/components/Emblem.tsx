import { memo } from "react";
import { SHIELD_LAYERS } from "../lib/format";

// Znak v hlavní kartě: animované energetické jádro a prstence. Vnější prstenec
// má 6 oblouků, jeden za každou ochrannou vrstvu; svítí jen běžící vrstvy.
// Animují se jen transformace a průhlednost (kompozitní vrstvy, bez sekání).

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

/** Energetické jádro: koule s plazmatem, pulzy a obíhajícími částicemi. */
export const Core = memo(function Core() {
  return (
    <div className="core" aria-hidden="true">
      <div className="core-pulse p1" />
      <div className="core-pulse p2" />
      <div className="core-pulse p3" />
      <div className="core-orbit o1">
        <span className="electron" />
      </div>
      <div className="core-orbit o2">
        <span className="electron" />
      </div>
      <div className="core-orbit o3">
        <span className="electron" />
      </div>
      <div className="core-plasma" />
      <div className="core-sphere">
        <div className="core-swirl" />
        <div className="core-swirl reverse" />
        <div className="core-gloss" />
      </div>
      <div className="core-heart" />
    </div>
  );
});

/** `layers`: tóny 6 vrstev oddělené čárkou (stabilní hodnota pro memo). */
export const Emblem = memo(function Emblem({ layers, scanning }: { layers: string; scanning: boolean }) {
  const tones = layers.split(",");
  const running = tones.filter((t) => t === "good").length;
  return (
    <figure className="emblem-wrap">
      <div
        className={`emblem${scanning ? " is-scanning" : ""}`}
        role="img"
        aria-label={`${running} ze ${SHIELD_LAYERS.length} ochranných vrstev běží${scanning ? ", kontrola probíhá" : ""}`}
      >
        <div className="emblem-halo" />
        <div className="ring-layer ring-dash">
          <svg viewBox="0 0 300 300" aria-hidden="true">
            <circle cx={C} cy={C} r="149" />
          </svg>
        </div>
        <div className="ring-layer ring-ticks">
          <svg viewBox="0 0 300 300" aria-hidden="true">
            {TICKS.map((deg) => (
              <line
                key={deg}
                x1={C}
                y1={C - 122}
                x2={C}
                y2={C - (deg % 30 === 0 ? 113 : 118)}
                transform={`rotate(${deg} ${C} ${C})`}
              />
            ))}
          </svg>
        </div>
        <svg className="ring-layer ring-arcs" viewBox="0 0 300 300" aria-hidden="true">
          <defs>
            <filter id="em-glow" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="3.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          {tones.map((tone, i) => (
            <path
              key={SHIELD_LAYERS[i] ?? i}
              d={arc(i)}
              pathLength={1}
              className={`layer-arc tone-${tone} a${i}`}
              filter={tone === "good" ? "url(#em-glow)" : undefined}
            />
          ))}
          <circle cx={C} cy={C} r="106" className="ring-thin" />
        </svg>
        <div className="emblem-sweep" />
        <Core />
      </div>
      <figcaption className="emblem-caption">
        {scanning ? (
          "Kontrola probíhá"
        ) : (
          <>
            <strong>{running}</strong> ze {SHIELD_LAYERS.length} vrstev běží
          </>
        )}
      </figcaption>
    </figure>
  );
});
