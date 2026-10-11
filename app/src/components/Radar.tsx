import { useEffect, useRef } from "react";
import { angleOf, onPulse, radiusOf } from "../lib/radar";

// Radar ochrany na plátně: otáčející se paprsek a body za skutečně
// zkontrolované položky (hlídání, programy, kontrola). Čistá položka „spadne“
// do jádra a vyšle z něj vlnu, hrozba zůstane rudě svítit. Nic si nevymýšlí:
// bez kontrol je radar prázdný a jen se otáčí.
// Výkon: jedna smyčka requestAnimationFrame, předkreslené záře, v nečinnosti
// 30 snímků za sekundu, při skrytém okně nebo omezení pohybu stojí.

interface Blip {
  angle: number;
  radius: number;
  born: number;
  threat: boolean;
  absorbed: boolean;
}

const LIFE_MS = 5200;
const THREAT_LIFE_MS = 18_000;
const MAX_BLIPS = 90;
const TAU = Math.PI * 2;

/** Předkreslená měkká záře (místo gradientu pro každý bod v každém snímku). */
function glowSprite(rgb: string): HTMLCanvasElement {
  const sprite = document.createElement("canvas");
  sprite.width = sprite.height = 64;
  const ctx = sprite.getContext("2d");
  if (ctx) {
    const g = ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
    g.addColorStop(0, `rgba(${rgb}, 0.95)`);
    g.addColorStop(0.25, `rgba(${rgb}, 0.45)`);
    g.addColorStop(1, `rgba(${rgb}, 0)`);
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, 64, 64);
  }
  return sprite;
}

const ease = (t: number) => t * t * (3 - 2 * t);

export function RadarCanvas({
  className,
  scanning,
  still,
  coreRatio = 0.33,
  rings = false,
}: {
  className?: string;
  scanning: boolean;
  still: boolean;
  /** Poloměr jádra jako podíl poloviny plátna (sem „padají“ čisté položky). */
  coreRatio?: number;
  /** Vlastní vodicí kružnice (samostatný radar bez prstenců znaku). */
  rings?: boolean;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const scanningRef = useRef(scanning);
  scanningRef.current = scanning;

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;
    const blue = glowSprite("110, 190, 255");
    const red = glowSprite("255, 95, 109");
    const blips: Blip[] = [];
    const waves: number[] = [];
    let size = 0;
    let dpr = 1;
    let sweep = -Math.PI / 2;
    let last = performance.now();
    let frame = 0;
    let running = false;
    let skip = false;

    const resize = () => {
      size = canvas.clientWidth;
      dpr = Math.min(window.devicePixelRatio || 1, 1.5);
      canvas.width = Math.max(1, Math.round(size * dpr));
      canvas.height = Math.max(1, Math.round(size * dpr));
    };
    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(canvas);

    const draw = (now: number) => {
      const dt = Math.min(64, now - last);
      last = now;
      const c = size / 2;
      const R = c * 0.97;
      const coreR = c * coreRatio;
      const scan = scanningRef.current;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, size, size);

      if (rings) {
        ctx.lineWidth = 1;
        for (const [f, a] of [
          [0.58, 0.16],
          [0.74, 0.12],
          [0.9, 0.1],
          [0.97, 0.22],
        ] as const) {
          ctx.strokeStyle = `rgba(110, 170, 255, ${a})`;
          ctx.beginPath();
          ctx.arc(c, c, c * f, 0, TAU);
          ctx.stroke();
        }
        ctx.strokeStyle = "rgba(110, 170, 255, 0.07)";
        ctx.beginPath();
        ctx.moveTo(c - R, c);
        ctx.lineTo(c + R, c);
        ctx.moveTo(c, c - R);
        ctx.lineTo(c, c + R);
        ctx.stroke();
      }

      // Paprsek: při kontrole rychlejší a jasnější.
      sweep = (sweep + (dt / (scan ? 1500 : 4200)) * TAU) % TAU;
      const tail = 1.1;
      ctx.beginPath();
      ctx.arc(c, c, R, sweep - tail, sweep);
      ctx.arc(c, c, coreR, sweep, sweep - tail, true);
      ctx.closePath();
      if (typeof ctx.createConicGradient === "function") {
        const beam = ctx.createConicGradient(sweep - tail, c, c);
        const end = tail / TAU;
        beam.addColorStop(0, "rgba(90, 170, 255, 0)");
        beam.addColorStop(end * 0.92, `rgba(110, 185, 255, ${scan ? 0.32 : 0.2})`);
        beam.addColorStop(end, `rgba(150, 210, 255, ${scan ? 0.46 : 0.3})`);
        beam.addColorStop(Math.min(1, end + 0.0005), "rgba(90, 170, 255, 0)");
        ctx.fillStyle = beam;
      } else {
        ctx.fillStyle = "rgba(90, 170, 255, 0.08)";
      }
      ctx.fill();
      ctx.strokeStyle = `rgba(170, 220, 255, ${scan ? 0.7 : 0.4})`;
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.moveTo(c + Math.cos(sweep) * coreR, c + Math.sin(sweep) * coreR);
      ctx.lineTo(c + Math.cos(sweep) * R, c + Math.sin(sweep) * R);
      ctx.stroke();

      // Jiskry obíhající jádro (dekorace jádra, ne kontroly).
      for (let i = 0; i < 14; i++) {
        const a = (i / 14) * TAU + now * (i % 2 ? 0.00031 : -0.00022);
        const r = coreR * (1.12 + 0.07 * Math.sin(now * 0.0011 + i * 1.7));
        const tw = 0.25 + 0.35 * (0.5 + 0.5 * Math.sin(now * 0.004 + i * 2.3));
        ctx.globalAlpha = tw;
        ctx.drawImage(blue, c + Math.cos(a) * r - 4, c + Math.sin(a) * r - 4, 8, 8);
      }
      ctx.globalAlpha = 1;

      let threatFlash = 0;
      for (let i = blips.length - 1; i >= 0; i--) {
        const b = blips[i];
        if (!b) continue;
        const age = now - b.born;
        const life = b.threat ? THREAT_LIFE_MS : LIFE_MS;
        if (age > life) {
          blips.splice(i, 1);
          continue;
        }
        const x = c + Math.cos(b.angle) * b.radius * c;
        const y = c + Math.sin(b.angle) * b.radius * c;
        const behind = (((sweep - b.angle) % TAU) + TAU) % TAU;
        const lit = behind < 0.7 ? 1 - behind / 0.7 : 0;
        const fadeIn = still ? 1 : Math.min(1, age / 180);
        const alpha = fadeIn * Math.pow(1 - age / life, 0.6) * (0.55 + 0.45 * lit);

        if (b.threat) {
          threatFlash = Math.max(threatFlash, 1 - Math.min(1, age / 1600));
          const beat = 0.6 + 0.4 * Math.sin(age * 0.008);
          ctx.globalAlpha = alpha * beat;
          ctx.drawImage(red, x - 16, y - 16, 32, 32);
          ctx.fillStyle = "rgba(255, 220, 224, 1)";
          ctx.beginPath();
          ctx.arc(x, y, 2.2, 0, TAU);
          ctx.fill();
          // Zaměřovač a spojnice k jádru.
          ctx.globalAlpha = alpha;
          ctx.strokeStyle = "rgba(255, 120, 130, 0.9)";
          ctx.lineWidth = 1.2;
          const spin = age * 0.0016;
          for (let k = 0; k < 4; k++) {
            const s = spin + (k * Math.PI) / 2;
            ctx.beginPath();
            ctx.arc(x, y, 9, s, s + 0.7);
            ctx.stroke();
          }
          if (age < 6000) {
            ctx.setLineDash([3, 4]);
            ctx.globalAlpha = alpha * 0.6 * (1 - age / 6000);
            ctx.beginPath();
            ctx.moveTo(x, y);
            ctx.lineTo(c + Math.cos(b.angle) * coreR, c + Math.sin(b.angle) * coreR);
            ctx.stroke();
            ctx.setLineDash([]);
          }
          const ring = (age % 1400) / 1400;
          ctx.globalAlpha = alpha * (1 - ring) * 0.8;
          ctx.beginPath();
          ctx.arc(x, y, 4 + ring * 18, 0, TAU);
          ctx.stroke();
        } else {
          ctx.globalAlpha = alpha;
          ctx.drawImage(blue, x - 11, y - 11, 22, 22);
          ctx.fillStyle = "rgba(225, 242, 255, 1)";
          ctx.beginPath();
          ctx.arc(x, y, 1.6, 0, TAU);
          ctx.fill();
          // Čistá položka „spadne“ do jádra a vyšle vlnu.
          const t = still ? 2 : (age - 160) / 760;
          if (t > 0 && t < 1) {
            const k = ease(t);
            const px = x + (c + Math.cos(b.angle) * coreR - x) * k;
            const py = y + (c + Math.sin(b.angle) * coreR - y) * k;
            ctx.globalAlpha = 0.9 * (1 - t * 0.4);
            ctx.drawImage(blue, px - 4, py - 4, 8, 8);
          } else if (t >= 1 && !b.absorbed) {
            b.absorbed = true;
            if (!still) waves.push(now);
          }
        }
        if (age < 900 && !still) {
          const k = age / 900;
          ctx.globalAlpha = (1 - k) * 0.6;
          ctx.strokeStyle = b.threat ? "rgba(255, 120, 130, 1)" : "rgba(150, 210, 255, 1)";
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.arc(x, y, 2 + k * 14, 0, TAU);
          ctx.stroke();
        }
      }

      // Vlny z jádra po každé zkontrolované položce.
      for (let i = waves.length - 1; i >= 0; i--) {
        const age = now - (waves[i] ?? 0);
        if (age > 760) {
          waves.splice(i, 1);
          continue;
        }
        const k = age / 760;
        ctx.globalAlpha = (1 - k) * 0.45;
        ctx.strokeStyle = "rgba(160, 215, 255, 1)";
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(c, c, coreR * (1 + k * 0.5), 0, TAU);
        ctx.stroke();
      }
      if (threatFlash > 0) {
        ctx.globalAlpha = threatFlash * 0.55;
        ctx.drawImage(red, c - coreR * 1.6, c - coreR * 1.6, coreR * 3.2, coreR * 3.2);
      }
      ctx.globalAlpha = 1;
    };

    const loop = (now: number) => {
      frame = requestAnimationFrame(loop);
      // V nečinnosti stačí poloviční snímková frekvence.
      const idle = !blips.length && !waves.length && !scanningRef.current;
      skip = idle && !skip;
      if (!skip) draw(now);
    };
    const start = () => {
      if (running) return;
      if (still || document.hidden) {
        draw(performance.now());
        return;
      }
      running = true;
      last = performance.now();
      frame = requestAnimationFrame(loop);
    };
    const stop = () => {
      running = false;
      cancelAnimationFrame(frame);
    };
    const onVisibility = () => (document.hidden ? stop() : start());
    const stopPulses = onPulse((pulse) => {
      blips.push({
        angle: angleOf(pulse.name) * TAU,
        radius: radiusOf(pulse.kind, pulse.name),
        born: performance.now(),
        threat: pulse.threat,
        absorbed: false,
      });
      if (blips.length > MAX_BLIPS) blips.splice(0, blips.length - MAX_BLIPS);
      if (!running) draw(performance.now());
    });
    document.addEventListener("visibilitychange", onVisibility);
    start();
    return () => {
      stop();
      stopPulses();
      observer.disconnect();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [still, coreRatio, rings]);

  return <canvas ref={canvasRef} className={className} aria-hidden="true" />;
}
