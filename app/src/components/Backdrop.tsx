import { useEffect, useRef } from "react";

// Pozadí hlavní karty: světelné paprsky, hory s odrazem na hladině a částice.
// Vše je dekorace (aria-hidden); při omezení pohybu zůstane statický obraz.

function rng(seed: number) {
  let s = seed;
  return () => {
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const W = 1200;
const H = 420;

/** Hřeben hor: několik vrcholů s rozeklaným obrysem. */
function ridge(seed: number, base: number, peaks: number, height: number, step: number): string {
  const r = rng(seed);
  const tops = Array.from({ length: peaks }, () => ({
    c: r() * W,
    h: height * (0.55 + r() * 0.45),
    w: 90 + r() * 170,
  }));
  let d = `M 0 ${H} L 0 ${base}`;
  for (let x = 0; x <= W; x += step) {
    let lift = 0;
    for (const p of tops) lift = Math.max(lift, p.h * Math.exp(-(((x - p.c) / p.w) ** 2)));
    const y = base - lift - (r() - 0.5) * 10;
    d += ` L ${x} ${y.toFixed(1)}`;
  }
  return `${d} L ${W} ${H} Z`;
}

const FAR = ridge(7, 292, 6, 235, 16);
const MID = ridge(21, 336, 7, 140, 14);
const NEAR = ridge(42, 372, 8, 70, 12);

function Particles({ intense }: { intense: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const speed = useRef(1);
  useEffect(() => {
    speed.current = intense ? 4 : 1;
  }, [intense]);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;
    const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    let w = 0;
    let h = 0;
    let frame = 0;
    type P = { x: number; y: number; r: number; vx: number; vy: number; a: number; t: number };
    let dots: P[] = [];

    const seed = () => {
      dots = Array.from({ length: 70 }, () => ({
        x: Math.random() * w,
        y: Math.random() * h,
        r: 0.4 + Math.random() * 1.7,
        vx: (Math.random() - 0.5) * 0.12,
        vy: -0.04 - Math.random() * 0.22,
        a: 0.25 + Math.random() * 0.6,
        t: Math.random() * Math.PI * 2,
      }));
    };
    const paint = () => {
      ctx.clearRect(0, 0, w, h);
      for (const p of dots) {
        const alpha = p.a * (0.55 + 0.45 * Math.sin(p.t));
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(150, 200, 255, ${alpha.toFixed(3)})`;
        ctx.fill();
      }
    };
    const step = () => {
      const k = speed.current;
      for (const p of dots) {
        p.x += p.vx * k;
        p.y += p.vy * k;
        p.t += 0.02 * k;
        if (p.y < -4) {
          p.y = h + 4;
          p.x = Math.random() * w;
        }
        if (p.x < -4) p.x = w + 4;
        if (p.x > w + 4) p.x = -4;
      }
      paint();
      frame = requestAnimationFrame(step);
    };
    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      w = rect.width;
      h = rect.height;
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      if (!dots.length) seed();
      paint();
    };
    const observer = new ResizeObserver(resize);
    observer.observe(canvas);
    const onVisibility = () => {
      cancelAnimationFrame(frame);
      if (!document.hidden && !still) frame = requestAnimationFrame(step);
    };
    document.addEventListener("visibilitychange", onVisibility);
    resize();
    if (!still) frame = requestAnimationFrame(step);
    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, []);

  return <canvas ref={canvasRef} className="particles" />;
}

export function Backdrop({ intense = false }: { intense?: boolean }) {
  return (
    <div className="backdrop" aria-hidden="true">
      <div className="rays" />
      <svg className="ridges" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMax slice">
        <defs>
          <linearGradient id="bd-far" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#1b4596" />
            <stop offset="1" stopColor="#0a1a44" />
          </linearGradient>
          <linearGradient id="bd-mid" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#10306e" />
            <stop offset="1" stopColor="#071433" />
          </linearGradient>
          <linearGradient id="bd-near" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#0a1c45" />
            <stop offset="1" stopColor="#040b20" />
          </linearGradient>
          <linearGradient id="bd-water" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#2a6cff" stopOpacity="0.35" />
            <stop offset="1" stopColor="#040b20" stopOpacity="0" />
          </linearGradient>
          <radialGradient id="bd-glint" cx="0.5" cy="0.5" r="0.5">
            <stop offset="0" stopColor="#9fd0ff" stopOpacity="0.45" />
            <stop offset="1" stopColor="#9fd0ff" stopOpacity="0" />
          </radialGradient>
          <filter id="bd-glow" x="-10%" y="-50%" width="120%" height="200%">
            <feGaussianBlur stdDeviation="3" />
          </filter>
        </defs>
        <g className="ridge far">
          <path d={FAR} fill="url(#bd-far)" />
          <path d={FAR} fill="none" stroke="#6fb1ff" strokeOpacity="0.55" strokeWidth="2" filter="url(#bd-glow)" />
        </g>
        <g className="ridge mid">
          <path d={MID} fill="url(#bd-mid)" />
          <path d={MID} fill="none" stroke="#4a8fff" strokeOpacity="0.35" strokeWidth="1.5" filter="url(#bd-glow)" />
        </g>
        <path className="ridge near" d={NEAR} fill="url(#bd-near)" />
        <rect y="392" width={W} height="28" fill="url(#bd-water)" />
        <ellipse className="glint" cx="600" cy="400" rx="260" ry="10" fill="url(#bd-glint)" />
      </svg>
      <Particles intense={intense} />
    </div>
  );
}
