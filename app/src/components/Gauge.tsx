import type { CareTone } from "../lib/care";

const TONE_TEXT: Record<CareTone, string> = { good: "V pořádku", caution: "Pozor", alert: "Brzdí" };

export function Gauge({
  value,
  tone,
  title,
  primary,
  secondary,
}: {
  value: number;
  tone: CareTone;
  title: string;
  primary: string;
  secondary: string;
}) {
  // Oblouk 270°: délka 0,75 obvodu kružnice s poloměrem 52.
  const arc = 2 * Math.PI * 52 * 0.75;
  const fill = Math.max(0, Math.min(1, value)) * arc;
  return (
    <figure className={`gauge tone-${tone}`}>
      <svg viewBox="0 0 128 128" aria-hidden="true">
        <circle className="gauge-track" cx="64" cy="64" r="52" strokeDasharray={`${arc} 999`} />
        <circle className="gauge-fill" cx="64" cy="64" r="52" strokeDasharray={`${fill} 999`} />
      </svg>
      <div className="gauge-center">
        <span className="gauge-primary">{primary}</span>
        <span className="gauge-tone">{TONE_TEXT[tone]}</span>
      </div>
      <figcaption>
        <span className="gauge-title">{title}</span>
        <span className="gauge-secondary">{secondary}</span>
      </figcaption>
    </figure>
  );
}
