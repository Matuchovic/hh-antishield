import { memo, type RefObject, useEffect, useRef, useState } from "react";
import { SHIELD_LAYERS } from "../lib/format";
import { onPulse } from "../lib/radar";
import { RadarCanvas } from "./Radar";

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
        <div className="core-alert" />
      </div>
      <div className="core-heart" />
    </div>
  );
});

/** Poslední zkontrolovaná položka pod znakem (nejvýš jednou za 450 ms, zmizí po 3,5 s). */
function useTicker(): { text: string; threat: boolean } | null {
  const [tick, setTick] = useState<{ text: string; threat: boolean } | null>(null);
  useEffect(() => {
    let shownAt = 0;
    let threatUntil = 0;
    let clear = 0;
    const stop = onPulse((pulse) => {
      const now = performance.now();
      // Hrozba zůstane vidět; běžné kontroly nejvýš jednou za 450 ms.
      if (!pulse.threat && (now < threatUntil || now - shownAt < 450)) return;
      shownAt = now;
      if (pulse.threat) threatUntil = now + 8000;
      setTick({ text: pulse.name, threat: pulse.threat });
      window.clearTimeout(clear);
      clear = window.setTimeout(() => setTick(null), pulse.threat ? 8000 : 3500);
    });
    return () => {
      stop();
      window.clearTimeout(clear);
    };
  }, []);
  return tick;
}

/** Náklon za kurzorem (jen posun vrstev, žádné 3D) a záblesk při hrozbě. */
function useEmblemMotion(ref: RefObject<HTMLDivElement | null>, still: boolean) {
  useEffect(() => {
    const el = ref.current;
    const hero = el?.closest<HTMLElement>(".hero");
    if (!el || !hero) return;
    let frame = 0;
    let hitTimer = 0;
    const onMove = (e: PointerEvent) => {
      if (still || frame) return;
      frame = requestAnimationFrame(() => {
        frame = 0;
        const r = el.getBoundingClientRect();
        const x = Math.max(-1, Math.min(1, (e.clientX - (r.left + r.width / 2)) / (r.width * 1.6)));
        const y = Math.max(-1, Math.min(1, (e.clientY - (r.top + r.height / 2)) / (r.height * 1.6)));
        el.style.setProperty("--px", x.toFixed(3));
        el.style.setProperty("--py", y.toFixed(3));
      });
    };
    const onLeave = () => {
      el.style.setProperty("--px", "0");
      el.style.setProperty("--py", "0");
    };
    const stopPulses = onPulse((pulse) => {
      if (!pulse.threat) return;
      el.classList.remove("is-hit");
      // Nové spuštění animace zásahu.
      void el.offsetWidth;
      el.classList.add("is-hit");
      window.clearTimeout(hitTimer);
      hitTimer = window.setTimeout(() => el.classList.remove("is-hit"), 1700);
    });
    hero.addEventListener("pointermove", onMove, { passive: true });
    hero.addEventListener("pointerleave", onLeave);
    return () => {
      cancelAnimationFrame(frame);
      window.clearTimeout(hitTimer);
      stopPulses();
      hero.removeEventListener("pointermove", onMove);
      hero.removeEventListener("pointerleave", onLeave);
    };
  }, [ref, still]);
}

/** `layers`: tóny 6 vrstev oddělené čárkou (stabilní hodnota pro memo). */
export const Emblem = memo(function Emblem({
  layers,
  scanning,
  still,
}: {
  layers: string;
  scanning: boolean;
  still: boolean;
}) {
  const tones = layers.split(",");
  const running = tones.filter((t) => t === "good").length;
  const ref = useRef<HTMLDivElement>(null);
  const calm = still || window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  useEmblemMotion(ref, calm);
  const tick = useTicker();
  return (
    <figure className="emblem-wrap">
      <div
        ref={ref}
        className={`emblem${scanning ? " is-scanning" : ""}`}
        role="img"
        aria-label={`${running} ze ${SHIELD_LAYERS.length} ochranných vrstev běží${scanning ? ", kontrola probíhá" : ""}`}
      >
        <div className="emblem-halo" />
        <RadarCanvas className="ring-layer radar-layer" scanning={scanning} still={calm} />
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
      <p className={`emblem-ticker${tick ? " is-on" : ""}${tick?.threat ? " is-threat" : ""}`} aria-hidden="true">
        {tick ? (
          <>
            <span>{tick.threat ? "Zachyceno" : "Zkontrolováno"}</span> {tick.text}
          </>
        ) : null}
      </p>
    </figure>
  );
});
