// Čištění a zrychlení: texty a výpočty pro rozhraní (bez volání backendu).
import { formatBytes } from "./format";
import type {
  CleanCategory,
  CleanItem,
  CleanMethod,
  CleanScan,
  MemoryPressure,
  SpeedReport,
  StartupEntry,
} from "./types";

export type CareTone = "good" | "caution" | "alert";

export interface CategoryMeta {
  label: string;
  what: string;
  /** Barva částic a značky kategorie (RGB). */
  rgb: string;
}

/** Pořadí kategorií od nejbezpečnějších (vytvoří se znovu) po soubory uživatele. */
export const CATEGORY_ORDER: CleanCategory[] = [
  "appCaches",
  "logs",
  "developer",
  "installers",
  "leftovers",
  "largeFiles",
  "trash",
];

export const CATEGORIES: Record<CleanCategory, CategoryMeta> = {
  appCaches: {
    label: "Mezipaměti aplikací",
    what: "Dočasná data, která si aplikace samy vytvoří znovu.",
    rgb: "90, 168, 255",
  },
  logs: {
    label: "Staré protokoly",
    what: "Záznamy a hlášení o pádech starší než týden.",
    rgb: "126, 222, 255",
  },
  developer: {
    label: "Vývojářské mezipaměti",
    what: "Xcode, simulátory, npm, Gradle a Cargo.",
    rgb: "160, 146, 255",
  },
  installers: {
    label: "Staré instalátory",
    what: "Instalační soubory ve Stažených starší než dva týdny.",
    rgb: "54, 211, 154",
  },
  leftovers: {
    label: "Zbytky po aplikacích",
    what: "Nastavení a stav oken aplikací, které už nemáte.",
    rgb: "242, 184, 75",
  },
  largeFiles: {
    label: "Velké staré soubory",
    what: "Vaše soubory nad 1 GB, půl roku beze změny.",
    rgb: "255, 138, 160",
  },
  trash: {
    label: "Koš",
    what: "Soubory, které jste už smazali.",
    rgb: "205, 216, 240",
  },
};

export function methodText(method: CleanMethod): string {
  switch (method) {
    case "delete":
      return "Smaže se, aplikace si to vytvoří znovu";
    case "moveToTrash":
      return "Přesune se do Koše, jde vrátit";
    case "emptyTrash":
      return "Vysypání je nevratné";
  }
}

const NOTES: Record<string, string> = {
  "app is running": "Aplikace běží. Zavřete ji, pak jde uklidit.",
  "in use": "Právě se používá, proto není předvybraná.",
  "rebuilt on next build": "Xcode je při dalším sestavení vytvoří znovu.",
  "downloaded again when a device connects": "Stáhne se znovu po připojení zařízení.",
  "app archives you may still need": "Archivy aplikací, které možná ještě potřebujete.",
  "downloaded again when needed": "Stáhne se znovu, až bude potřeba.",
  "app not found": "Aplikace už není nainstalovaná.",
  "your file": "Váš soubor. Uklidí se, jen když ho vyberete.",
  permanent: "Nevratné.",
};

export function noteText(note: string | null): string | null {
  if (!note) return null;
  return NOTES[note] ?? null;
}

const CHANGED = new Set([
  "outside home",
  "invalid path",
  "symbolic link",
  "not allowed here",
  "method not allowed",
]);

export function failureText(reason: string): string {
  if (CHANGED.has(reason)) return "Položka se od hledání změnila, proto zůstala na místě.";
  if (reason === "no longer exists") return "Položka už neexistuje.";
  return "Nepodařilo se ji uklidit. Možná ji právě používá jiná aplikace.";
}

/** Předvybrané: doporučené položky kromě Koše (ten se vysypává zvlášť). */
export function defaultSelection(scan: CleanScan): Set<string> {
  return new Set(
    scan.items.filter((i) => i.recommended && i.method !== "emptyTrash").map((i) => i.id),
  );
}

export interface Selected {
  /** Uvolní se hned (smazání). */
  freed: number;
  /** Jde do Koše (uvolní se až po jeho vysypání). */
  trashed: number;
  total: number;
  count: number;
}

export function selectedBytes(scan: CleanScan, selected: ReadonlySet<string>): Selected {
  const out: Selected = { freed: 0, trashed: 0, total: 0, count: 0 };
  for (const item of scan.items) {
    if (!selected.has(item.id) || item.method === "emptyTrash") continue;
    if (item.method === "moveToTrash") out.trashed += item.bytes;
    else out.freed += item.bytes;
    out.total += item.bytes;
    out.count += 1;
  }
  return out;
}

export interface CategoryGroup {
  category: CleanCategory;
  items: CleanItem[];
  bytes: number;
}

export function groupByCategory(scan: CleanScan): CategoryGroup[] {
  return CATEGORY_ORDER.map((category) => {
    const items = scan.items.filter((i) => i.category === category);
    return { category, items, bytes: items.reduce((sum, i) => sum + i.bytes, 0) };
  }).filter((group) => group.items.length > 0);
}

/** Kolik zabírá Koš (položka jen s plným přístupem k disku). */
export function trashItem(scan: CleanScan): CleanItem | null {
  return scan.items.find((i) => i.method === "emptyTrash") ?? null;
}

const GB = 1_000_000_000;

export function diskTone(disk: SpeedReport["disk"]): CareTone {
  if (!disk || disk.total <= 0) return "good";
  const share = disk.free / disk.total;
  if (share < 0.1 || disk.free < 10 * GB) return "alert";
  if (share < 0.2 || disk.free < 25 * GB) return "caution";
  return "good";
}

export const PRESSURE_TEXT: Record<MemoryPressure, string> = {
  normal: "Paměti je dost",
  warning: "Paměti začíná být málo",
  critical: "Paměti je kriticky málo",
};

export function memoryTone(memory: SpeedReport["memory"]): CareTone {
  if (memory.pressure === "critical") return "alert";
  if (memory.pressure === "warning") return "caution";
  if (memory.pressure === "normal") return "good";
  return memory.total > 0 && memory.used / memory.total > 0.92 ? "caution" : "good";
}

export function cpuTone(cpu: number): CareTone {
  if (cpu >= 85) return "alert";
  if (cpu >= 60) return "caution";
  return "good";
}

const DAY = 86_400;

export function uptimeText(secs: number): string {
  const days = Math.floor(secs / DAY);
  const hours = Math.floor((secs % DAY) / 3600);
  const minutes = Math.floor((secs % 3600) / 60);
  if (days > 0) {
    const unit = days === 1 ? "den" : days < 5 ? "dny" : "dní";
    return hours > 0 ? `${days} ${unit} ${hours} h` : `${days} ${unit}`;
  }
  if (hours > 0) return `${hours} h ${minutes} min`;
  return `${minutes} min`;
}

/** Po týdnu bez restartu stojí za to restartovat (paměť, aktualizace). */
export function uptimeTone(secs: number): CareTone {
  return secs > 7 * DAY ? "caution" : "good";
}

/** Doporučení z měření: jen to, co měření skutečně ukázalo. */
export function speedAdvice(report: SpeedReport): { tone: CareTone; text: string }[] {
  const advice: { tone: CareTone; text: string }[] = [];
  const disk = diskTone(report.disk);
  if (report.disk && disk !== "good") {
    advice.push({
      tone: disk,
      text: `Na disku zbývá ${formatBytes(report.disk.free)}. Uvolněte místo, systém pak znovu zrychlí.`,
    });
  }
  const memory = memoryTone(report.memory);
  if (memory !== "good") {
    advice.push({
      tone: memory,
      text: "Paměti je málo. Ukončete aplikace, které jí zabírají nejvíc.",
    });
  }
  if (report.memory.swapUsed > 2 * GB) {
    advice.push({
      tone: "caution",
      text: `Systém odkládá ${formatBytes(report.memory.swapUsed)} paměti na disk. Pomůže ukončit náročné aplikace nebo restart.`,
    });
  }
  const cpu = cpuTone(report.cpu);
  if (cpu !== "good") {
    advice.push({
      tone: cpu,
      text: `Procesor je vytížený na ${Math.round(report.cpu)} %. Podívejte se, která aplikace ho zatěžuje.`,
    });
  }
  if (report.uptimeSecs > 7 * DAY) {
    advice.push({
      tone: uptimeTone(report.uptimeSecs),
      text: `Počítač běží ${uptimeText(report.uptimeSecs)} bez restartu. Restart uvolní paměť a dokončí aktualizace.`,
    });
  }
  return advice;
}

function baseName(path: string): string {
  const name = path.split(/[\\/]/).filter(Boolean).pop() ?? path;
  return name.replace(/\.(app|exe|lnk|desktop|plist)$/i, "");
}

/** Čitelné jméno položky po přihlášení: program, jinak jméno ze souboru. */
export function startupName(entry: StartupEntry): string {
  if (entry.program) return baseName(entry.program);
  return entry.label || baseName(entry.plist);
}
