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

function Particles({ intense, still }: { intense: boolean; still: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const speed = useRef(1);
  useEffect(() => {
    speed.current = intense ? 4 : 1;
  }, [intense]);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;
    const frozen = still || window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    // Měkké tečky nepotřebují plné rozlišení Retina; menší plátno = levnější snímek.
    const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
    let w = 0;
    let h = 0;
    let frame = 0;
    let last = 0;
    type P = { x: number; y: number; r: number; vx: number; vy: number; a: number; t: number };
    let dots: P[] = [];

    const seed = () => {
      dots = Array.from({ length: 56 }, () => ({
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
    const step = (now: number) => {
      // Pohyb podle času, ne podle počtu snímků (stejná rychlost při 60 i 120 Hz).
      const k = speed.current * Math.min(last ? (now - last) / 16.7 : 1, 3);
      last = now;
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
    let visible = true;
    const io = new IntersectionObserver(([entry]) => {
      const now = entry?.isIntersecting ?? true;
      if (now === visible) return;
      visible = now;
      cancelAnimationFrame(frame);
      last = 0;
      if (visible && !frozen && !document.hidden) frame = requestAnimationFrame(step);
    });
    io.observe(canvas);
    const onVisibility = () => {
      cancelAnimationFrame(frame);
      last = 0;
      if (!document.hidden && !frozen && visible) frame = requestAnimationFrame(step);
    };
    document.addEventListener("visibilitychange", onVisibility);
    resize();
    if (!frozen) frame = requestAnimationFrame(step);
    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      io.disconnect();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [still]);

  return <canvas ref={canvasRef} className="particles" />;
}

function Ridge({ className, path, fill, stops, rim }: {
  className: string;
  path: string;
  fill: string;
  stops: [string, string];
  rim?: { color: string; opacity: number; width: number };
}) {
  return (
    <div className={`ridge ${className}`}>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMax slice" aria-hidden="true">
        <defs>
          <linearGradient id={fill} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor={stops[0]} />
            <stop offset="1" stopColor={stops[1]} />
          </linearGradient>
          {rim ? (
            <filter id={`${fill}-glow`} x="-10%" y="-50%" width="120%" height="200%">
              <feGaussianBlur stdDeviation="3" />
            </filter>
          ) : null}
        </defs>
        <path d={path} fill={`url(#${fill})`} />
        {rim ? (
          <path
            d={path}
            fill="none"
            stroke={rim.color}
            strokeOpacity={rim.opacity}
            strokeWidth={rim.width}
            filter={`url(#${fill}-glow)`}
          />
        ) : null}
      </svg>
    </div>
  );
}

export function Backdrop({ intense = false, still = false }: { intense?: boolean; still?: boolean }) {
  // Každý hřeben je vlastní vrstva: posouvá se transformací bez překreslování.
  return (
    <div className="backdrop" aria-hidden="true">
      <div className="rays" />
      <div className="ridges">
        <Ridge className="far" path={FAR} fill="bd-far" stops={["#1b4596", "#0a1a44"]} rim={{ color: "#6fb1ff", opacity: 0.55, width: 2 }} />
        <Ridge className="mid" path={MID} fill="bd-mid" stops={["#10306e", "#071433"]} rim={{ color: "#4a8fff", opacity: 0.35, width: 1.5 }} />
        <Ridge className="near" path={NEAR} fill="bd-near" stops={["#0a1c45", "#040b20"]} />
        <div className="water" />
        <div className="glint" />
      </div>
      <Particles intense={intense} still={still} />
    </div>
  );
}
