// Znělky a zvuky událostí. Vše se syntetizuje ve Web Audio, žádné zvukové
// soubory (bez licencí třetích stran). Vypínají se v Nastavení.

let enabled = true;
let context: AudioContext | null = null;

export function setSoundEnabled(value: boolean): void {
  enabled = value;
}

function audio(): AudioContext | null {
  if (!enabled) return null;
  try {
    context ??= new AudioContext();
    if (context.state === "suspended") void context.resume();
    return context;
  } catch {
    return null;
  }
}

// Některé webview pustí zvuk až po první interakci; pak kontext probudíme.
if (typeof window !== "undefined") {
  const wake = () => {
    if (context?.state === "suspended") void context.resume();
  };
  window.addEventListener("pointerdown", wake, { passive: true });
  window.addEventListener("keydown", wake);
}

interface Tone {
  freq: number;
  start: number;
  duration: number;
  type?: OscillatorType;
  gain?: number;
  glideTo?: number;
}

function master(ctx: AudioContext, volume: number): GainNode {
  const out = ctx.createGain();
  out.gain.value = volume;
  const compressor = ctx.createDynamicsCompressor();
  out.connect(compressor);
  compressor.connect(ctx.destination);
  return out;
}

function play(tones: Tone[], volume = 0.18): void {
  const ctx = audio();
  if (!ctx) return;
  const out = master(ctx, volume);
  const now = ctx.currentTime + 0.02;
  for (const t of tones) {
    const osc = ctx.createOscillator();
    const env = ctx.createGain();
    osc.type = t.type ?? "sine";
    osc.frequency.setValueAtTime(t.freq, now + t.start);
    if (t.glideTo) osc.frequency.exponentialRampToValueAtTime(t.glideTo, now + t.start + t.duration);
    const peak = t.gain ?? 0.6;
    env.gain.setValueAtTime(0.0001, now + t.start);
    env.gain.exponentialRampToValueAtTime(peak, now + t.start + Math.min(0.04, t.duration / 4));
    env.gain.exponentialRampToValueAtTime(0.0001, now + t.start + t.duration);
    osc.connect(env);
    env.connect(out);
    osc.start(now + t.start);
    osc.stop(now + t.start + t.duration + 0.05);
  }
}

/** Šumový „whoosh“ s filtrem (energie, přesun). */
function whoosh(start: number, duration: number, from: number, to: number, volume = 0.12): void {
  const ctx = audio();
  if (!ctx) return;
  const length = Math.floor(ctx.sampleRate * duration);
  const buffer = ctx.createBuffer(1, length, ctx.sampleRate);
  const data = buffer.getChannelData(0);
  for (let i = 0; i < length; i++) data[i] = (Math.random() * 2 - 1) * (1 - i / length);
  const source = ctx.createBufferSource();
  source.buffer = buffer;
  const filter = ctx.createBiquadFilter();
  filter.type = "bandpass";
  filter.Q.value = 1.2;
  const t0 = ctx.currentTime + 0.02 + start;
  filter.frequency.setValueAtTime(from, t0);
  filter.frequency.exponentialRampToValueAtTime(to, t0 + duration);
  const env = ctx.createGain();
  env.gain.setValueAtTime(0.0001, t0);
  env.gain.exponentialRampToValueAtTime(volume, t0 + duration * 0.3);
  env.gain.exponentialRampToValueAtTime(0.0001, t0 + duration);
  source.connect(filter);
  filter.connect(env);
  env.connect(master(ctx, 1));
  source.start(t0);
}

/** Znělka při spuštění: nabíjení jádra a akord. */
export function playIntro(): void {
  whoosh(0, 1.1, 180, 2400, 0.1);
  play(
    [
      { freq: 110, start: 0, duration: 1.4, type: "sine", gain: 0.5, glideTo: 220 },
      { freq: 220, start: 0.9, duration: 1.6, type: "triangle", gain: 0.35 },
      { freq: 277.18, start: 1.0, duration: 1.5, type: "triangle", gain: 0.3 },
      { freq: 329.63, start: 1.1, duration: 1.5, type: "triangle", gain: 0.3 },
      { freq: 440, start: 1.2, duration: 1.4, type: "sine", gain: 0.28 },
      { freq: 1318.5, start: 1.25, duration: 0.9, type: "sine", gain: 0.12 },
      { freq: 1760, start: 1.4, duration: 0.8, type: "sine", gain: 0.08 },
    ],
    0.16,
  );
}

export function playScanStart(): void {
  play([
    { freq: 392, start: 0, duration: 0.18, type: "triangle", gain: 0.4, glideTo: 587.33 },
    { freq: 783.99, start: 0.12, duration: 0.25, type: "sine", gain: 0.25 },
  ]);
}

export function playScanDone(clean: boolean): void {
  if (clean) {
    play([
      { freq: 523.25, start: 0, duration: 0.35, type: "sine", gain: 0.4 },
      { freq: 659.25, start: 0.12, duration: 0.4, type: "sine", gain: 0.35 },
      { freq: 783.99, start: 0.24, duration: 0.6, type: "sine", gain: 0.3 },
    ]);
  } else {
    playThreat();
  }
}

export function playThreat(): void {
  play(
    [
      { freq: 659.25, start: 0, duration: 0.22, type: "square", gain: 0.18 },
      { freq: 493.88, start: 0.22, duration: 0.3, type: "square", gain: 0.18 },
      { freq: 659.25, start: 0.6, duration: 0.22, type: "square", gain: 0.14 },
      { freq: 493.88, start: 0.82, duration: 0.35, type: "square", gain: 0.14 },
    ],
    0.14,
  );
}

export function playCleaned(): void {
  whoosh(0, 0.5, 2400, 300, 0.1);
  play([
    { freq: 587.33, start: 0.35, duration: 0.25, type: "sine", gain: 0.35 },
    { freq: 880, start: 0.47, duration: 0.45, type: "sine", gain: 0.3 },
  ]);
}
