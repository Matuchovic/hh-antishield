import { useEffect, useRef } from "react";
import type { FleetTone } from "../lib/fleet";
import type { FleetCommandKind, FleetCommandState } from "../lib/types";
import { particleCount } from "./Vortex";

// Mapa firemních Maců. Jádro uprostřed je tento Mac (správce), firemní Macy
// kolem něj. Spojnice ukazují skutečné spojení se schránkou, záblesky jen
// skutečné příkazy: podepsaný příkaz letí k Macu, výsledek úklidu se vrací
// jako částice podle uvolněné velikosti. Příkaz pro offline Mac čeká ve
// schránce (bod na spojnici), dokud se Mac nepřipojí.
// Výkon jako u jádra čištění: jedna smyčka requestAnimationFrame, v klidu
// 30 snímků za sekundu, při skrytém okně stojí, při omezení pohybu je statická.

export interface FleetNode {
  id: string;
  label: string;
  sub: string;
  tone: FleetTone;
  /** Na Macu čeká nezneškodněná hrozba (poplach na mapě). */
  threat: boolean;
  online: boolean;
  /** Zaplněný disk (0–1), když ho Mac nahlásil. */
  diskUsed: number | null;
  /** Poslední příkaz (spouští jednorázové animace při změně stavu). */
  command: { id: string; kind: FleetCommandKind; state: FleetCommandState; bytes: number } | null;
}

const TAU = Math.PI * 2;
const PARK = 0.7;

const TONE_RGB: Record<FleetTone, string> = {
  good: "90, 168, 255",
  caution: "242, 184, 75",
  alert: "255, 95, 109",
};
const OFF_RGB = "126, 144, 182";
const RETURN_RGB = ["90, 168, 255", "126, 222, 255", "160, 146, 255", "235, 245, 255"];

/** Poloha Macu kolem jádra (podíl šířky a výšky plátna). */
export function nodeLayout(i: number, n: number): { x: number; y: number; depth: number } {
  const start = n <= 2 ? 0 : -Math.PI / 2;
  const a = start + (i / Math.max(1, n)) * TAU;
  return { x: 0.5 + Math.cos(a) * 0.4, y: 0.47 + Math.sin(a) * 0.33, depth: (Math.sin(a) + 1) / 2 };
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

interface Packet {
  nodeId: string;
  start: number;
  from: number;
  to: number;
}

interface Bit {
  nodeId: string;
  start: number;
  duration: number;
  lane: number;
  rgb: string;
}

export function FleetMap({
  nodes,
  focus,
  still,
  onFocus,
  onSelect,
  coreLabel,
  coreSub,
}: {
  nodes: FleetNode[];
  focus: string | null;
  still: boolean;
  onFocus: (id: string | null) => void;
  onSelect: (id: string) => void;
  coreLabel: string;
  coreSub: string;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const props = useRef({ nodes, focus });
  props.current = { nodes, focus };
  const sync = useRef<() => void>(() => {});

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;
    const sprites = new Map<string, HTMLCanvasElement>();
    const sprite = (rgb: string) => {
      let s = sprites.get(rgb);
      if (!s) {
        s = glowSprite(rgb);
        sprites.set(rgb, s);
      }
      return s;
    };
    const halo = glowSprite("90, 168, 255", 0.8);
    const seen = new Map<string, string>();
    const packets: Packet[] = [];
    const bits: Bit[] = [];
    const flashes: { nodeId: string; at: number; rgb: string }[] = [];
    let width = 0;
    let height = 0;
    let dpr = 1;
    let last = performance.now();
    let frame = 0;
    let running = false;
    let skip = false;
    let heat = 0;
    let waveAt = -1;
    let wasReturning = false;

    const resize = () => {
      width = canvas.clientWidth;
      height = canvas.clientHeight;
      dpr = Math.min(window.devicePixelRatio || 1, 1.75);
      canvas.width = Math.max(1, Math.round(width * dpr));
      canvas.height = Math.max(1, Math.round(height * dpr));
      if (!running) draw(performance.now());
    };

    const geometry = (index: number, count: number) => {
      const { x, y, depth } = nodeLayout(index, count);
      const cx = width / 2;
      const cy = height * 0.47;
      const nx = x * width;
      const ny = y * height;
      const dx = nx - cx;
      const dy = ny - cy;
      const len = Math.hypot(dx, dy) || 1;
      const bow = len * 0.14;
      return {
        cx,
        cy,
        nx,
        ny,
        depth,
        qx: (cx + nx) / 2 - (dy / len) * bow,
        qy: (cy + ny) / 2 + (dx / len) * bow,
      };
    };
    type Geo = ReturnType<typeof geometry>;
    const at = (g: Geo, t: number) => {
      const u = 1 - t;
      return {
        x: u * u * g.cx + 2 * u * t * g.qx + t * t * g.nx,
        y: u * u * g.cy + 2 * u * t * g.qy + t * t * g.ny,
      };
    };

    /** Změny příkazů spustí jednorázové animace (příkaz, výsledek). */
    const reconcile = () => {
      const now = performance.now();
      for (const node of props.current.nodes) {
        const cmd = node.command;
        const signature = cmd ? `${cmd.id}:${cmd.state}` : "";
        const previous = seen.get(node.id);
        seen.set(node.id, signature);
        if (previous === undefined || previous === signature || !cmd || still) continue;
        const [previousId, previousState] = previous.split(":");
        if (previousId !== cmd.id) {
          heat = Math.min(1.4, heat + 0.35);
          packets.push({ nodeId: node.id, start: now, from: 0, to: cmd.state === "queued" ? PARK : 1 });
        } else if (previousState === "queued" && cmd.state !== "queued") {
          packets.push({ nodeId: node.id, start: now, from: PARK, to: 1 });
        }
        if (cmd.state === "done") {
          if (cmd.kind === "cleanup" && cmd.bytes > 0) {
            const count = Math.min(64, particleCount(cmd.bytes));
            for (let i = 0; i < count; i++) {
              bits.push({
                nodeId: node.id,
                start: now + i * 26 + Math.random() * 240,
                duration: 1050 + Math.random() * 520,
                lane: (Math.random() - 0.5) * 2,
                rgb: RETURN_RGB[i % RETURN_RGB.length] ?? RETURN_RGB[0] ?? "90, 168, 255",
              });
            }
          } else {
            flashes.push({ nodeId: node.id, at: now, rgb: "54, 211, 154" });
          }
        } else if (cmd.state === "failed" || cmd.state === "declined" || cmd.state === "expired") {
          flashes.push({ nodeId: node.id, at: now, rgb: TONE_RGB.caution });
        }
      }
      if (!running) draw(now);
    };
    sync.current = reconcile;

    const draw = (now: number) => {
      const dt = Math.min(64, now - last);
      last = now;
      const { nodes: list, focus: focused } = props.current;
      const count = list.length;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, width, height);
      const cx = width / 2;
      const cy = height * 0.47;
      const coreR = Math.min(width * 0.055, height * 0.1);
      const geos = new Map<string, Geo>();
      list.forEach((node, i) => geos.set(node.id, geometry(i, count)));

      // Dráha Maců a pomalý odlesk po ní.
      const rx = width * 0.4;
      const ry = height * 0.33;
      ctx.strokeStyle = "rgba(120, 175, 255, 0.1)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.ellipse(cx, cy, rx, ry, 0, 0, TAU);
      ctx.stroke();
      ctx.strokeStyle = "rgba(120, 175, 255, 0.05)";
      ctx.beginPath();
      ctx.ellipse(cx, cy, rx * 0.62, ry * 0.62, 0, 0, TAU);
      ctx.stroke();
      if (!still) {
        const sweep = (now * 0.00022) % TAU;
        const shimmer = ctx.createLinearGradient(
          cx + Math.cos(sweep) * rx,
          cy + Math.sin(sweep) * ry,
          cx + Math.cos(sweep - 0.9) * rx,
          cy + Math.sin(sweep - 0.9) * ry,
        );
        shimmer.addColorStop(0, "rgba(150, 205, 255, 0.45)");
        shimmer.addColorStop(1, "rgba(150, 205, 255, 0)");
        ctx.strokeStyle = shimmer;
        ctx.lineWidth = 1.6;
        ctx.beginPath();
        ctx.ellipse(cx, cy, rx, ry, 0, sweep - 0.9, sweep);
        ctx.stroke();
      }

      // Spojnice se schránkou.
      list.forEach((node) => {
        const g = geos.get(node.id);
        if (!g) return;
        const rgb = node.online ? TONE_RGB[node.tone] : OFF_RGB;
        const isFocus = focused === node.id;
        const line = ctx.createLinearGradient(g.cx, g.cy, g.nx, g.ny);
        line.addColorStop(0, `rgba(90, 168, 255, ${isFocus ? 0.5 : 0.08})`);
        line.addColorStop(1, `rgba(${rgb}, ${isFocus ? 0.85 : node.online ? 0.42 : 0.2})`);
        ctx.strokeStyle = line;
        ctx.lineWidth = isFocus ? 1.8 : 1.1;
        ctx.setLineDash(node.online ? [] : [3, 6]);
        ctx.beginPath();
        ctx.moveTo(g.cx, g.cy);
        ctx.quadraticCurveTo(g.qx, g.qy, g.nx, g.ny);
        ctx.stroke();
      });
      ctx.setLineDash([]);

      ctx.globalCompositeOperation = "lighter";
      // Pravidelné hlášení online Maců (abstrakce spojení, ne skutečný počet).
      if (!still) {
        list.forEach((node, i) => {
          const g = geos.get(node.id);
          if (!g || !node.online) return;
          const period = 4600;
          const phase = (now + i * 830) % period;
          if (phase > 1500) return;
          const t = 1 - ease(phase / 1500);
          const p = at(g, t);
          ctx.globalAlpha = Math.sin((phase / 1500) * Math.PI) * 0.7;
          const s = 10;
          ctx.drawImage(sprite(TONE_RGB[node.tone]), p.x - s / 2, p.y - s / 2, s, s);
        });
      }

      // Příkazy na cestě k Macům (kometa se stopou).
      for (let i = packets.length - 1; i >= 0; i--) {
        const packet = packets[i];
        const g = packet ? geos.get(packet.nodeId) : undefined;
        if (!packet || !g) {
          packets.splice(i, 1);
          continue;
        }
        const k = Math.min(1, (now - packet.start) / 900);
        const t = packet.from + (packet.to - packet.from) * ease(k);
        for (let trail = 0; trail < 7; trail++) {
          const tt = Math.max(packet.from, t - trail * 0.03);
          const p = at(g, tt);
          ctx.globalAlpha = (1 - trail / 7) * 0.95;
          const s = 18 - trail * 2;
          ctx.drawImage(sprite("225, 240, 255"), p.x - s / 2, p.y - s / 2, s, s);
        }
        if (k >= 1) {
          packets.splice(i, 1);
          if (packet.to === 1) flashes.push({ nodeId: packet.nodeId, at: now, rgb: "190, 225, 255" });
        }
      }

      // Výsledky úklidu se vracejí k jádru.
      let returning = false;
      for (let i = bits.length - 1; i >= 0; i--) {
        const bit = bits[i];
        const g = bit ? geos.get(bit.nodeId) : undefined;
        if (!bit || !g) {
          bits.splice(i, 1);
          continue;
        }
        if (now < bit.start) {
          returning = true;
          continue;
        }
        const k = (now - bit.start) / bit.duration;
        if (k >= 1) {
          bits.splice(i, 1);
          heat = Math.min(1.5, heat + 0.035);
          continue;
        }
        returning = true;
        const t = 1 - ease(k);
        const p = at(g, t);
        const spread = Math.sin(k * Math.PI) * 9 * bit.lane;
        const dx = g.nx - g.cx;
        const dy = g.ny - g.cy;
        const len = Math.hypot(dx, dy) || 1;
        ctx.globalAlpha = Math.min(1, k * 5) * 0.9;
        const s = 9 + (1 - k) * 4;
        ctx.drawImage(sprite(bit.rgb), p.x - (dy / len) * spread - s / 2, p.y + (dx / len) * spread - s / 2, s, s);
      }
      if (returning) wasReturning = true;
      else if (wasReturning) {
        wasReturning = false;
        waveAt = now;
        heat = Math.min(1.6, heat + 0.4);
      }
      heat = Math.max(0, heat - dt * 0.001);
      ctx.globalAlpha = 1;

      // Rázová vlna po návratu výsledků.
      const waveAge = waveAt < 0 ? Infinity : now - waveAt;
      if (waveAge < 1200) {
        const k = ease(waveAge / 1200);
        ctx.globalCompositeOperation = "source-over";
        ctx.strokeStyle = `rgba(190, 228, 255, ${(1 - k) * 0.7})`;
        ctx.lineWidth = 2.6 - k * 1.8;
        ctx.beginPath();
        ctx.ellipse(cx, cy, coreR + rx * k, coreR + ry * k, 0, 0, TAU);
        ctx.stroke();
        ctx.globalCompositeOperation = "lighter";
      }

      // Jádro: tento Mac.
      const glow = 0.45 + heat * 0.45;
      ctx.globalAlpha = Math.min(1, glow);
      const hs = coreR * (4.4 + heat * 1.3);
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
      ctx.strokeStyle = `rgba(170, 220, 255, ${0.55 + heat * 0.3})`;
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, TAU);
      ctx.stroke();
      // Prstenec jádra (podpis příkazů).
      ctx.strokeStyle = `rgba(150, 205, 255, ${0.22 + heat * 0.3})`;
      ctx.setLineDash([2, 5]);
      ctx.beginPath();
      ctx.arc(cx, cy, r * 1.55, still ? 0 : now * 0.0004, (still ? 0 : now * 0.0004) + TAU);
      ctx.stroke();
      ctx.setLineDash([]);

      // Macy.
      list.forEach((node) => {
        const g = geos.get(node.id);
        if (!g) return;
        const scale = 0.84 + 0.26 * g.depth;
        const rgb = node.online ? TONE_RGB[node.tone] : OFF_RGB;
        const isFocus = focused === node.id;
        const cmd = node.command;
        const pulse = still ? 0.5 : 0.5 + 0.5 * Math.sin(now * 0.0026 + g.nx);

        ctx.globalCompositeOperation = "lighter";
        ctx.globalAlpha = node.online ? 0.75 + pulse * 0.25 : 0.35;
        const gs = (isFocus ? 70 : 56) * scale;
        ctx.drawImage(sprite(rgb), g.nx - gs / 2, g.ny - gs / 2, gs, gs);
        ctx.globalAlpha = 1;
        ctx.globalCompositeOperation = "source-over";

        // Poplach: rozbíhající se kruh u hrozby.
        if (node.threat && node.online && !still) {
          const age = (now % 1700) / 1700;
          ctx.strokeStyle = `rgba(${TONE_RGB.alert}, ${(1 - age) * 0.7})`;
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.arc(g.nx, g.ny, (12 + age * 22) * scale, 0, TAU);
          ctx.stroke();
        }

        // Disk: zaplněná část prstence.
        const ringR = 15 * scale;
        ctx.lineWidth = 2.4;
        ctx.strokeStyle = "rgba(140, 170, 230, 0.16)";
        ctx.beginPath();
        ctx.arc(g.nx, g.ny, ringR, 0, TAU);
        ctx.stroke();
        if (node.diskUsed !== null) {
          ctx.strokeStyle = `rgba(${rgb}, ${node.online ? 0.95 : 0.5})`;
          ctx.lineCap = "round";
          ctx.beginPath();
          ctx.arc(g.nx, g.ny, ringR, -Math.PI / 2, -Math.PI / 2 + TAU * Math.min(1, node.diskUsed));
          ctx.stroke();
          ctx.lineCap = "butt";
        }

        // Tělo Macu.
        const dot = 6.5 * scale;
        const fill = ctx.createRadialGradient(g.nx - dot * 0.35, g.ny - dot * 0.4, 0, g.nx, g.ny, dot);
        fill.addColorStop(0, node.online ? "rgba(245, 250, 255, 1)" : "rgba(200, 210, 230, 0.8)");
        fill.addColorStop(1, `rgba(${rgb}, ${node.online ? 1 : 0.6})`);
        ctx.fillStyle = fill;
        ctx.beginPath();
        ctx.arc(g.nx, g.ny, dot, 0, TAU);
        ctx.fill();
        if (isFocus) {
          ctx.strokeStyle = "rgba(235, 245, 255, 0.9)";
          ctx.lineWidth = 1.4;
          ctx.beginPath();
          ctx.arc(g.nx, g.ny, ringR + 6, 0, TAU);
          ctx.stroke();
        }

        // Příkaz běží: točící se oblouk; čeká na souhlas: pomalý jantarový.
        if (cmd && (cmd.state === "delivered" || cmd.state === "running" || cmd.state === "awaitingConsent")) {
          const consent = cmd.state === "awaitingConsent";
          const spin = still ? 0 : now * (consent ? 0.0015 : 0.006);
          ctx.strokeStyle = consent ? `rgba(${TONE_RGB.caution}, 0.9)` : "rgba(225, 242, 255, 0.95)";
          ctx.lineWidth = 2;
          ctx.lineCap = "round";
          ctx.beginPath();
          ctx.arc(g.nx, g.ny, ringR + 5, spin, spin + (consent ? 0.9 : 1.6));
          ctx.stroke();
          if (consent) {
            ctx.beginPath();
            ctx.arc(g.nx, g.ny, ringR + 5, spin + Math.PI, spin + Math.PI + 0.9);
            ctx.stroke();
          }
          ctx.lineCap = "butt";
        }

        // Příkaz čeká ve schránce na offline Mac.
        if (cmd?.state === "queued" && !packets.some((p) => p.nodeId === node.id)) {
          const p = at(g, PARK);
          const blink = still ? 1 : 0.55 + 0.45 * Math.sin(now * 0.005);
          ctx.globalCompositeOperation = "lighter";
          ctx.globalAlpha = blink;
          ctx.drawImage(sprite("225, 240, 255"), p.x - 9, p.y - 9, 18, 18);
          ctx.globalAlpha = 1;
          ctx.globalCompositeOperation = "source-over";
        }
      });

      // Záblesky (příkaz doručen, kontrola hotová, odmítnutí).
      for (let i = flashes.length - 1; i >= 0; i--) {
        const flash = flashes[i];
        const g = flash ? geos.get(flash.nodeId) : undefined;
        if (!flash || !g) {
          flashes.splice(i, 1);
          continue;
        }
        const k = (now - flash.at) / 700;
        if (k >= 1) {
          flashes.splice(i, 1);
          continue;
        }
        ctx.strokeStyle = `rgba(${flash.rgb}, ${(1 - k) * 0.9})`;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(g.nx, g.ny, 14 + ease(k) * 18, 0, TAU);
        ctx.stroke();
      }
    };

    const loop = (now: number) => {
      frame = requestAnimationFrame(loop);
      const busy = packets.length > 0 || bits.length > 0 || flashes.length > 0 || heat > 0.05;
      skip = !busy && !skip;
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

  const signature = nodes
    .map((n) => `${n.id}:${n.tone}:${n.online ? 1 : 0}:${n.command?.id ?? ""}:${n.command?.state ?? ""}`)
    .join("|");
  useEffect(() => {
    sync.current();
  }, [signature, focus]);

  return (
    <div className="fleet-map">
      <canvas ref={canvasRef} className="fleet-canvas" aria-hidden="true" />
      <div className="fleet-core-label" aria-hidden="true">
        <span>{coreLabel}</span>
        <span>{coreSub}</span>
      </div>
      {nodes.map((node, i) => {
        const { x, y } = nodeLayout(i, nodes.length);
        return (
          <button
            key={node.id}
            type="button"
            className={`fleet-node tone-${node.tone}${node.online ? " is-online" : ""}${focus === node.id ? " is-focus" : ""}`}
            style={{ left: `${x * 100}%`, top: `${y * 100}%` }}
            onMouseEnter={() => onFocus(node.id)}
            onMouseLeave={() => onFocus(null)}
            onFocus={() => onFocus(node.id)}
            onBlur={() => onFocus(null)}
            onClick={() => onSelect(node.id)}
            aria-label={`${node.label}: ${node.sub}`}
          >
            <span className="fleet-node-hit" aria-hidden="true" />
            <span className="fleet-node-label">{node.label}</span>
            <span className="fleet-node-sub">{node.sub}</span>
          </button>
        );
      })}
    </div>
  );
}
