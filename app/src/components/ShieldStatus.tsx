// „Poctivý štít“: každý oblouk je jedna ochranná vrstva. Svítí jen ta,
// kterou engine hlásí jako běžící a ověřenou; neexistující vrstvy jsou
// čárkované. Štít tak nikdy nevypadá plnější, než ochrana skutečně je.
import { COMPONENT_LABELS, SHIELD_LAYERS, stateTone } from "../lib/format";
import type { ComponentStatus } from "../lib/types";

const SIZE = 220;
const CENTER = SIZE / 2;
const RADIUS = 96;
const GAP_DEG = 8;

function polar(angleDeg: number, radius: number) {
  const rad = ((angleDeg - 90) * Math.PI) / 180;
  return { x: CENTER + radius * Math.cos(rad), y: CENTER + radius * Math.sin(rad) };
}

function arc(startDeg: number, endDeg: number) {
  const start = polar(startDeg, RADIUS);
  const end = polar(endDeg, RADIUS);
  const large = endDeg - startDeg > 180 ? 1 : 0;
  return `M ${start.x} ${start.y} A ${RADIUS} ${RADIUS} 0 ${large} 1 ${end.x} ${end.y}`;
}

export function ShieldStatus({ components }: { components: ComponentStatus[] }) {
  const step = 360 / SHIELD_LAYERS.length;
  const layers = SHIELD_LAYERS.map((kind, i) => {
    const status = components.find((c) => c.kind === kind);
    const tone = status ? stateTone(status.state) : "off";
    return { kind, tone, start: i * step + GAP_DEG / 2, end: (i + 1) * step - GAP_DEG / 2 };
  });
  const running = layers.filter((l) => l.tone === "good").length;
  const label = `Běží ${running} ze ${layers.length} ochranných vrstev: ${layers
    .map((l) => `${COMPONENT_LABELS[l.kind]} ${l.tone === "good" ? "běží" : "neběží"}`)
    .join(", ")}`;

  return (
    <figure className="shield" aria-label={label}>
      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} role="img" aria-hidden="true">
        {layers.map((layer) => (
          <path
            key={layer.kind}
            d={arc(layer.start, layer.end)}
            className={`shield-arc tone-${layer.tone}`}
          />
        ))}
        <path
          className="shield-body"
          d="M110 52 L152 68 V104 C152 132 134 152 110 164 C86 152 68 132 68 104 V68 Z"
        />
        <path className="shield-inner" d="M110 66 L140 77.5 V104 C140 124 127 139 110 148 Z" />
      </svg>
      <figcaption>
        <span className="shield-count">{running}</span> ze {layers.length} vrstev běží
      </figcaption>
    </figure>
  );
}
