import { useEffect, useRef } from "react";
import { CATEGORIES, CATEGORY_ORDER } from "../lib/care";
import type { CleanCategory } from "../lib/types";

// Jádro čištění na plátně: nalezená data obíhají jádro jako částice v disku,
// každá kategorie na vlastní dráze. Počet částic odpovídá skutečné velikosti
// (logaritmicky), nic si nevymýšlí: před hledáním je disk prázdný. Při úklidu
// jádro „pohltí“ přesně to, co se uklidilo; co zůstalo, obíhá dál.
// Výkon: jedna smyčka requestAnimationFrame, předkreslené záře, v klidu
// 30 snímků za sekundu, při skrytém okně stojí, při omezení pohybu je statické.

export type VortexPhase = "idle" | "scanning" | "ready" | "cleaning" | "done";

export interface VortexGroup {
  category: CleanCategory;
  bytes: number;
  selected: boolean;
}

interface Particle {
  cat: CleanCategory;
  /** Domovská dráha (podíl poloměru disku). */
  home: number;
  r: number;
  a: number;
  speed: number;
  size: number;
  seed: number;
  born: number;
  /** Pohlcení: kdy začne (ms), jinak null. */
  absorbAt: number | null;
}

const TAU = Math.PI * 2;
const TILT = 0.34;
const MAX_TOTAL = 520;
const BASE_SPEED = 0.00016;

/** Počet částic podle velikosti: 20 MB ≈ 14, 1 GB ≈ 51, 10 GB ≈ 78. */
export function particleCount(bytes: number): number {
  if (bytes <= 0) return 0;
  return Math.round(Math.min(96, 6 + Math.log2(1 + bytes / 20e6) * 8));
}

function glowSprite(rgb: string, core = 0.95): HTMLCanvasElement {
  const sprite = document.createElement("canvas");
  sprite.width = sprite.height = 64;
  const ctx = sprite.getContext("2d");
  if (ctx) {
    const g = ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
    g.addColorStop(0, `rgba(${rgb}, ${core})`);
    g.addColorStop(0.22, `rgba(${rgb}, ${core * 0.5})`);
    g.addColorStop(1, `rgba(${rgb}, 0)`);
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, 64, 64);
  }
  return sprite;
}

const ease = (t: number) => 1 - (1 - t) ** 3;

/** Dráha kategorie: vnitřní pro mezipaměti, vnější pro soubory uživatele. */
function band(cat: CleanCategory): [number, number] {
  const i = Math.max(0, CATEGORY_ORDER.indexOf(cat));
  const from = 0.3 + i * 0.1;
  return [from, from + 0.085];
}

export function Vortex({
  phase,
  groups,
  active,
  focus,
  still,
}: {
  phase: VortexPhase;
  groups: VortexGroup[];
  /** Kategorie, kterou hledání právě prochází. */
  active: CleanCategory | null;
  /** Zvýrazněná kategorie (najetí na legendu). */
  focus: CleanCategory | null;
  still: boolean;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const props = useRef({ phase, groups, active, focus });
  props.current = { phase, groups, active, focus };
  const sync = useRef<() => void>(() => {});

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;
    const sprites = new Map<string, HTMLCanvasElement>();
    for (const cat of CATEGORY_ORDER) sprites.set(cat, glowSprite(CATEGORIES[cat].rgb));
    const halo = glowSprite("90, 168, 255", 0.8);
    const white = glowSprite("235, 245, 255");
    const particles: Particle[] = [];
    let width = 0;
    let height = 0;
    let dpr = 1;
    let last = performance.now();
    let frame = 0;
    let running = false;
    let skip = false;
    let heat = 0;
    let beam = -Math.PI / 2;
    let waveAt = -1;
    let wasAbsorbing = false;
    const sparks: { x: number; y: number; at: number; cat: CleanCategory }[] = [];

    const resize = () => {
      width = canvas.clientWidth;
      height = canvas.clientHeight;
      dpr = Math.min(window.devicePixelRatio || 1, 1.75);
      canvas.width = Math.max(1, Math.round(width * dpr));
      canvas.height = Math.max(1, Math.round(height * dpr));
      if (!running) draw(performance.now());
    };

    /** Srovná částice se skutečnými velikostmi kategorií. */
    const reconcile = () => {
      const now = performance.now();
      const { groups: current, phase: p } = props.current;
      const wanted = new Map<CleanCategory, number>();
      for (const g of current) wanted.set(g.category, particleCount(g.bytes));
      const total = [...wanted.values()].reduce((s, n) => s + n, 0);
      const scale = total > MAX_TOTAL ? MAX_TOTAL / total : 1;
      for (const cat of CATEGORY_ORDER) {
        const target = Math.round((wanted.get(cat) ?? 0) * scale);
        const living = particles.filter((q) => q.cat === cat && q.absorbAt === null);
        if (living.length > target) {
          // Pohltí se ty nejblíž jádru (úklid je přitáhl).
          living.sort((x, y) => x.r - y.r);
          living.slice(0, living.length - target).forEach((q, i) => {
            q.absorbAt = now + (still ? 0 : Math.min(900, i * 14) + Math.random() * 220);
          });
        } else {
          const [from, to] = band(cat);
          for (let i = living.length; i < target; i++) {
            const home = from + Math.random() * (to - from);
            particles.push({
              cat,
              home,
              r: still || p === "idle" ? home : 1.2 + Math.random() * 0.25,
              a: Math.random() * TAU,
              speed: 0.85 + Math.random() * 0.3,
              size: 0.8 + Math.random() * 1.5,
              seed: Math.random() * 1000,
              born: now + (still ? 0 : Math.random() * 700),
              absorbAt: null,
            });
          }
        }
      }
      if (still) {
        for (let i = particles.length - 1; i >= 0; i--) {
          if (particles[i]?.absorbAt !== null) particles.splice(i, 1);
        }
      }
      if (!running) draw(now);
    };
    sync.current = reconcile;

    const draw = (now: number) => {
      const dt = Math.min(64, now - last);
      last = now;
      const { phase: p, groups: current, active: act, focus: foc } = props.current;
      const cx = width / 2;
      const cy = height / 2;
      const R = width * 0.47;
      const coreR = Math.min(width * 0.08, height * 0.2);
      const selected = new Set(current.filter((g) => g.selected).map((g) => g.category));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, width, height);

      // Tělo disku a dráhy kategorií (v nakloněné rovině).
      ctx.save();
      ctx.translate(cx, cy);
      ctx.scale(1, TILT);
      if (particles.length) {
        const body = ctx.createRadialGradient(0, 0, coreR, 0, 0, R);
        body.addColorStop(0, "rgba(47, 128, 255, 0.16)");
        body.addColorStop(0.55, "rgba(47, 128, 255, 0.06)");
        body.addColorStop(1, "rgba(47, 128, 255, 0)");
        ctx.fillStyle = body;
        ctx.beginPath();
        ctx.arc(0, 0, R, 0, TAU);
        ctx.fill();
      }
      // Paprsek hledání.
      if (p === "scanning") {
        beam += dt * 0.0032;
        const conic = (ctx as CanvasRenderingContext2D & {
          createConicGradient?: (a: number, x: number, y: number) => CanvasGradient;
        }).createConicGradient?.(beam - 1.1, 0, 0);
        if (conic) {
          conic.addColorStop(0, "rgba(150, 210, 255, 0)");
          conic.addColorStop(0.17, "rgba(150, 210, 255, 0.28)");
          conic.addColorStop(0.175, "rgba(150, 210, 255, 0)");
          conic.addColorStop(1, "rgba(150, 210, 255, 0)");
          ctx.fillStyle = conic;
          ctx.beginPath();
          ctx.arc(0, 0, R, 0, TAU);
          ctx.fill();
        }
      }
      ctx.restore();
      // Dráhy kategorií (elipsy kreslené bez zkosení, aby měly stejnou tloušťku).
      for (const cat of CATEGORY_ORDER) {
        const [from, to] = band(cat);
        const isActive = p === "scanning" && act === cat;
        const isFocus = foc === cat;
        const pulse = 0.5 + 0.5 * Math.sin(now * 0.008);
        const alpha = isActive ? 0.35 + pulse * 0.35 : isFocus ? 0.6 : 0.08;
        const ring = R * ((from + to) / 2);
        ctx.strokeStyle = `rgba(${isActive || isFocus ? CATEGORIES[cat].rgb : "120, 175, 255"}, ${alpha})`;
        ctx.lineWidth = isActive || isFocus ? 1.8 : 1;
        ctx.beginPath();
        ctx.ellipse(cx, cy, ring, ring * TILT, 0, 0, TAU);
        ctx.stroke();
      }
      // Rázová vlna po dokončeném úklidu.
      const waveAge = waveAt < 0 ? Infinity : now - waveAt;
      if (waveAge < 1100) {
        const k = ease(waveAge / 1100);
        const ring = coreR + (R * 1.05 - coreR) * k;
        ctx.strokeStyle = `rgba(190, 228, 255, ${(1 - k) * 0.85})`;
        ctx.lineWidth = 3 - k * 2;
        ctx.beginPath();
        ctx.ellipse(cx, cy, ring, ring * TILT, 0, 0, TAU);
        ctx.stroke();
      }

      // Pohyb částic.
      const cleaning = p === "cleaning";
      let absorbing = false;
      for (let i = particles.length - 1; i >= 0; i--) {
        const q = particles[i];
        if (!q) continue;
        const charged = cleaning && selected.has(q.cat);
        let goal = q.home;
        if (q.absorbAt !== null && now >= q.absorbAt) {
          absorbing = true;
          goal = 0;
        } else if (charged) {
          goal = q.home * 0.62;
        }
        if (now >= q.born) {
          const pull = q.absorbAt !== null && now >= q.absorbAt ? 0.0036 : charged ? 0.0022 : 0.0019;
          q.r += (goal - q.r) * Math.min(1, dt * pull);
        }
        const omega = BASE_SPEED * q.speed * Math.max(q.r, 0.08) ** -1.5 * (charged ? 2.2 : 1);
        q.a = (q.a + dt * omega) % TAU;
        if (q.absorbAt !== null && q.r * R < coreR * 0.9) {
          particles.splice(i, 1);
          heat = Math.min(1.4, heat + 0.045);
          if (sparks.length < 40) {
            sparks.push({ x: Math.cos(q.a) * coreR * 0.8, y: Math.sin(q.a) * coreR * 0.3, at: now, cat: q.cat });
          }
        }
      }
      if (absorbing) wasAbsorbing = true;
      else if (wasAbsorbing) {
        wasAbsorbing = false;
        waveAt = now;
        heat = Math.min(1.6, heat + 0.4);
      }
      heat = Math.max(0, heat - dt * 0.0011);

      const drawParticles = (front: boolean) => {
        ctx.globalCompositeOperation = "lighter";
        for (const q of particles) {
          const depth = Math.sin(q.a);
          if ((depth >= 0) !== front || now < q.born) continue;
          const x = cx + Math.cos(q.a) * q.r * R;
          const y = cy + depth * q.r * R * TILT;
          const near = (depth + 1) / 2;
          const fadeIn = Math.min(1, (now - q.born) / 500);
          const outside = q.r > 1 ? Math.max(0, 1 - (q.r - 1) * 3) : 1;
          const dim = selected.size === 0 || selected.has(q.cat) ? 1 : 0.32;
          const focusBoost = foc === null ? 1 : foc === q.cat ? 1.35 : 0.45;
          const twinkle = 0.86 + 0.14 * Math.sin(now * 0.004 + q.seed);
          ctx.globalAlpha = Math.min(1, fadeIn * outside * dim * focusBoost * twinkle * (0.5 + 0.5 * near));
          const s = q.size * (0.75 + 0.5 * near) * 7;
          const sprite = sprites.get(q.cat) ?? white;
          ctx.drawImage(sprite, x - s / 2, y - s / 2, s, s);
        }
        ctx.globalAlpha = 1;
        ctx.globalCompositeOperation = "source-over";
      };

      drawParticles(false);

      // Výtrysky z pólů jádra: síla podle práce (hledání, úklid, pohlcení).
      const energy = Math.min(1, 0.22 + heat * 0.55 + (p === "scanning" || cleaning ? 0.25 : 0));
      const flicker = still ? 1 : 0.9 + 0.1 * Math.sin(now * 0.013);
      ctx.globalCompositeOperation = "lighter";
      for (const dir of [-1, 1]) {
        const length = height * 0.46;
        const jet = ctx.createLinearGradient(cx, cy, cx, cy + dir * length);
        jet.addColorStop(0, `rgba(170, 220, 255, ${0.55 * energy * flicker})`);
        jet.addColorStop(0.35, `rgba(90, 168, 255, ${0.18 * energy})`);
        jet.addColorStop(1, "rgba(90, 168, 255, 0)");
        ctx.fillStyle = jet;
        ctx.beginPath();
        ctx.moveTo(cx - coreR * 0.42, cy);
        ctx.quadraticCurveTo(cx - coreR * 0.16, cy + dir * length * 0.5, cx - coreR * 0.5, cy + dir * length);
        ctx.lineTo(cx + coreR * 0.5, cy + dir * length);
        ctx.quadraticCurveTo(cx + coreR * 0.16, cy + dir * length * 0.5, cx + coreR * 0.42, cy);
        ctx.closePath();
        ctx.fill();
      }
      ctx.globalCompositeOperation = "source-over";

      // Horký vnitřní prstenec: strana, která se k nám otáčí, svítí víc.
      const hot = (front: boolean) => {
        const rx = coreR * 1.6;
        const ry = rx * TILT;
        const doppler = ctx.createLinearGradient(cx - rx, cy, cx + rx, cy);
        const a = Math.min(1, 0.45 + heat * 0.4 + (cleaning ? 0.2 : 0));
        doppler.addColorStop(0, `rgba(225, 242, 255, ${a})`);
        doppler.addColorStop(0.5, `rgba(130, 190, 255, ${a * 0.6})`);
        doppler.addColorStop(1, `rgba(70, 130, 240, ${a * 0.25})`);
        ctx.globalCompositeOperation = "lighter";
        ctx.strokeStyle = doppler;
        for (const [width, alpha] of [
          [7, 0.18],
          [1.8, 1],
        ] as const) {
          ctx.lineWidth = width;
          ctx.globalAlpha = alpha;
          ctx.beginPath();
          ctx.ellipse(cx, cy, rx, ry, 0, front ? 0 : Math.PI, front ? Math.PI : TAU);
          ctx.stroke();
        }
        ctx.globalAlpha = 1;
        ctx.globalCompositeOperation = "source-over";
      };
      hot(false);

      // Jádro.
      const glow = 0.4 + heat * 0.45 + (p === "scanning" || cleaning ? 0.12 : 0);
      ctx.globalCompositeOperation = "lighter";
      ctx.globalAlpha = Math.min(1, glow);
      const hs = coreR * (4.2 + heat * 1.2);
      ctx.drawImage(halo, cx - hs / 2, cy - hs / 2, hs, hs);
      ctx.globalAlpha = 1;
      ctx.globalCompositeOperation = "source-over";
      const breathe = still ? 1 : 1 + Math.sin(now * 0.0021) * 0.025 + heat * 0.05;
      const r = coreR * breathe;
      const body = ctx.createRadialGradient(cx - r * 0.32, cy - r * 0.38, r * 0.05, cx, cy, r);
      body.addColorStop(0, "rgba(240, 248, 255, 1)");
      body.addColorStop(0.28, "rgba(150, 205, 255, 1)");
      body.addColorStop(0.72, "rgba(44, 112, 240, 1)");
      body.addColorStop(1, "rgba(10, 36, 118, 1)");
      ctx.fillStyle = body;
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, TAU);
      ctx.fill();
      // Plazma v jádře (dva pomalé oblouky).
      ctx.lineWidth = 1.4;
      for (const [k, off] of [
        [1, 0],
        [-1.4, 2.1],
      ] as const) {
        const turn = still ? off : now * 0.0007 * k + off;
        ctx.strokeStyle = `rgba(225, 242, 255, ${0.28 + heat * 0.3})`;
        ctx.beginPath();
        ctx.ellipse(cx, cy, r * 0.62, r * 0.28, turn, 0.3, 2.4);
        ctx.stroke();
      }
      ctx.strokeStyle = `rgba(170, 220, 255, ${0.55 + heat * 0.3})`;
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, TAU);
      ctx.stroke();
      // Záblesky pohlcených částic.
      ctx.globalCompositeOperation = "lighter";
      for (let i = sparks.length - 1; i >= 0; i--) {
        const spark = sparks[i];
        if (!spark) continue;
        const age = now - spark.at;
        if (age > 420) {
          sparks.splice(i, 1);
          continue;
        }
        ctx.globalAlpha = (1 - age / 420) * 0.9;
        const s = coreR * (0.5 + age / 300);
        ctx.drawImage(sprites.get(spark.cat) ?? white, cx + spark.x - s / 2, cy + spark.y - s / 2, s, s);
      }
      ctx.globalAlpha = 1;
      ctx.globalCompositeOperation = "source-over";

      hot(true);
      drawParticles(true);
    };

    const loop = (now: number) => {
      frame = requestAnimationFrame(loop);
      const { phase: p } = props.current;
      const busy = p === "scanning" || p === "cleaning" || wasAbsorbing || heat > 0.05;
      const settling = particles.some((q) => Math.abs(q.r - q.home) > 0.01 || q.absorbAt !== null);
      // V klidu stačí poloviční snímková frekvence.
      skip = !busy && !settling && !skip;
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
    const observer = new ResizeObserver(resize);
    observer.observe(canvas);
    resize();
    reconcile();
    document.addEventListener("visibilitychange", onVisibility);
    start();
    return () => {
      stop();
      observer.disconnect();
      document.removeEventListener("visibilitychange", onVisibility);
      sync.current = () => {};
    };
  }, [still]);

  // Nové velikosti (výsledek hledání nebo úklidu) srovnají částice; statické
  // plátno se překreslí i po změně výběru nebo zvýraznění.
  const signature = groups.map((g) => `${g.category}:${g.bytes}:${g.selected ? 1 : 0}`).join("|");
  useEffect(() => {
    sync.current();
  }, [signature, phase, active, focus]);

  return <canvas ref={canvasRef} className="vortex-canvas" aria-hidden="true" />;
}
