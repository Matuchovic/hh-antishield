// Radar ochrany: jednotlivé skutečné kontroly („pulzy“) pro animaci. Plátno se
// k nim přihlásí samo, takže React kvůli každé kontrole nepřekresluje.
import type { ActivityKind } from "./types";

export type PulseKind = ActivityKind | "scan";

export interface Pulse {
  kind: PulseKind;
  name: string;
  threat: boolean;
  atMs: number;
}

type Listener = (pulse: Pulse) => void;
const listeners = new Set<Listener>();

export function onPulse(listener: Listener): () => void {
  listeners.add(listener);
  return () => void listeners.delete(listener);
}

export function emitPulse(pulse: Pulse): void {
  for (const listener of listeners) listener(pulse);
}

/** Stabilní úhel (0–1) podle názvu: stejný soubor bliká na stejném místě. */
export function angleOf(name: string): number {
  let hash = 2166136261;
  for (let i = 0; i < name.length; i++) {
    hash ^= name.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0) / 4294967296;
}

/** Pásmo radaru (podíl poloměru) podle druhu kontroly: venku stažené, uvnitř programy. */
export const BANDS: Record<PulseKind, [number, number]> = {
  download: [0.86, 0.95],
  mail: [0.78, 0.86],
  file: [0.74, 0.84],
  scan: [0.6, 0.95],
  program: [0.64, 0.72],
  startup: [0.56, 0.62],
};

/** Poloměr v pásmu: stabilní podle názvu. */
export function radiusOf(kind: PulseKind, name: string): number {
  const [from, to] = BANDS[kind];
  return from + (to - from) * angleOf(`${name}#r`);
}
