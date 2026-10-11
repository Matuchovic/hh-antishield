// Příběh útoku: z uložených faktů (původ, spuštění, nález, zásah) skládá
// srozumitelnou časovou osu, shrnutí a doporučení. Nic si nedomýšlí: krok,
// o kterém nic nevíme, se buď vynechá, nebo řekne, že údaj chybí.
import type { Channel, Severity, Story } from "./types";
import { displayPath, formatDateTime, formatTime } from "./format";

export type StepIcon = "globe" | "mail" | "drive" | "folder" | "play" | "power" | "shield" | "box" | "alert";
export type StepTone = "neutral" | "good" | "caution" | "alert";

export interface StoryStep {
  id: string;
  icon: StepIcon;
  title: string;
  /** Čas kroku (ms), pokud ho známe. */
  atMs: number | null;
  lines: string[];
  tone: StepTone;
}

export const SEVERITY_LABELS: Record<Severity, string> = {
  test_only: "testovací",
  low: "nízká",
  medium: "střední",
  high: "vysoká",
  critical: "kritická",
};

const CHANNEL_TITLES: Record<Channel, string> = {
  web: "Staženo z internetu",
  email: "Příloha e-mailu",
  airDrop: "Přišlo přes AirDrop",
  messages: "Přišlo ve Zprávách",
  externalDrive: "Z externího disku",
  unknown: "Původ neznámý",
};

const CHANNEL_ICONS: Record<Channel, StepIcon> = {
  web: "globe",
  email: "mail",
  airDrop: "drive",
  messages: "mail",
  externalDrive: "drive",
  unknown: "folder",
};

/** `https://cdn.example.com/a.zip` → `cdn.example.com`. */
export function hostOf(url: string | null): string | null {
  if (!url) return null;
  const match = /^[a-z]+:\/\/([^/]+)/i.exec(url);
  return match?.[1] ?? null;
}

export function fileName(path: string): string {
  return path.split(/[\\/]/).filter(Boolean).pop() ?? path;
}

function folderOf(path: string): string {
  const shown = displayPath(path);
  const cut = Math.max(shown.lastIndexOf("/"), shown.lastIndexOf("\\"));
  return cut > 0 ? shown.slice(0, cut) : shown;
}

/** Krátká délka: „2 s“, „5 min“, „3 h 10 min“, „2 dny“. */
export function shortDuration(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s} s`;
  const min = Math.round(s / 60);
  if (min < 60) return `${min} min`;
  const h = Math.floor(min / 60);
  if (h < 48) return min % 60 ? `${h} h ${min % 60} min` : `${h} h`;
  const days = Math.round(h / 24);
  return days < 5 ? `${days} dny` : `${days} dní`;
}

/** Kdy hrozba dorazila: značka systému, jinak vytvoření souboru. */
export function arrivedAt(story: Story): number | null {
  return story.provenance.arrivedAtMs ?? story.provenance.createdAtMs ?? null;
}

function savedByText(app: string | null): string | null {
  return app ? `Uložila aplikace ${app}` : null;
}

export function storySteps(story: Story): StoryStep[] {
  const { provenance: p, finding, chain, outcome } = story;
  const steps: StoryStep[] = [];
  const origin: string[] = [];
  if (p.channel === "web") {
    const page = hostOf(p.referrerUrl);
    const host = hostOf(p.downloadUrl);
    if (page) origin.push(`Ze stránky ${page}`);
    if (p.downloadUrl) origin.push(page && host === page ? `Soubor: ${p.downloadUrl}` : `Adresa souboru: ${p.downloadUrl}`);
  }
  if (p.emailFrom) origin.push(`Od: ${p.emailFrom}`);
  const saved = savedByText(p.savedBy);
  if (saved) origin.push(saved);
  if (p.channel === "unknown" && !origin.length) {
    origin.push("Systém k souboru nezapsal, odkud pochází (běžné u souborů vytvořených v počítači nebo rozbalených z archivu).");
  }
  steps.push({
    id: "origin",
    icon: CHANNEL_ICONS[p.channel],
    title: CHANNEL_TITLES[p.channel],
    atMs: arrivedAt(story),
    lines: origin,
    tone: "neutral",
  });

  const where = [displayPath(finding.path)];
  if (finding.archiveEntry) where.push(`Uvnitř archivu: ${finding.archiveEntry}`);
  steps.push({
    id: "disk",
    icon: "folder",
    title: `Uloženo ve složce ${fileName(folderOf(finding.path))}`,
    atMs: null,
    lines: where,
    tone: "neutral",
  });

  if (chain.length) {
    const [process, parent] = chain;
    const lines = [parent ? `Spustil ho ${parent.name}` : "Spouštějící proces už není známý"];
    if (chain.length > 1) lines.push(`Řetěz spuštění: ${[...chain].reverse().map((l) => l.name).join(" → ")}`);
    steps.push({
      id: "launch",
      icon: "play",
      title: `Program ${process?.name ?? fileName(finding.path)} se spustil`,
      atMs: process?.startedAtMs ?? null,
      lines,
      tone: "caution",
    });
  } else if (finding.origin?.type === "process") {
    steps.push({
      id: "launch",
      icon: "play",
      title: `Program ${finding.origin.name} běžel`,
      atMs: null,
      lines: ["Kdo ho spustil, se už nedalo zjistit (proces mezitím skončil)."],
      tone: "caution",
    });
  }
  if (finding.origin?.type === "startupItem") {
    steps.push({
      id: "persist",
      icon: "power",
      title: "Zapsal se do spouštění po přihlášení",
      atMs: null,
      lines: [finding.origin.label || displayPath(finding.origin.location)],
      tone: "caution",
    });
  }

  const detected: string[] = [`${finding.ruleName}, závažnost ${SEVERITY_LABELS[finding.severity]}`];
  const arrived = arrivedAt(story);
  if (arrived !== null && story.detectedAtMs >= arrived && story.detectedAtMs - arrived < 30 * 86_400_000) {
    detected.push(`${shortDuration(story.detectedAtMs - arrived)} po příchodu souboru`);
  }
  steps.push({
    id: "detect",
    icon: "shield",
    title: {
      realtime: "Zachyceno hlídáním složek",
      program: "Zachyceno po spuštění programu",
      startup: "Zachyceno v položkách po přihlášení",
      scan: "Nalezeno při kontrole",
    }[story.source],
    atMs: story.detectedAtMs,
    lines: detected,
    tone: "alert",
  });

  switch (outcome.type) {
    case "quarantined":
      steps.push({
        id: "outcome",
        icon: "box",
        title: outcome.processTerminated ? "Program ukončen a izolován v karanténě" : "Izolováno v karanténě",
        atMs: story.updatedAtMs,
        lines: ["Soubor je znehodnocený a nic nespustí. V Karanténě ho jde obnovit nebo smazat."],
        tone: "good",
      });
      break;
    case "reported":
      steps.push({
        id: "outcome",
        icon: "alert",
        title: "Čeká na vaše rozhodnutí",
        atMs: null,
        lines: ["Nález je méně jistý, proto ho AntiShield jen nahlásil. Vyčištěním ho přesunete do karantény."],
        tone: "caution",
      });
      break;
    case "failed":
      steps.push({
        id: "outcome",
        icon: "alert",
        title: "Izolace se nepovedla",
        atMs: story.updatedAtMs,
        lines: [outcome.reason],
        tone: "alert",
      });
      break;
  }
  return steps;
}

/** Jedna věta: odkud, kdy a jak to skončilo. */
export function storySummary(story: Story): string {
  const { provenance: p, finding, outcome } = story;
  const name = fileName(finding.path);
  const arrived = arrivedAt(story);
  const when = arrived !== null ? ` ${formatDateTime(arrived)}` : "";
  const page = hostOf(p.referrerUrl) ?? hostOf(p.downloadUrl);
  const via = p.savedBy ? ` (${p.savedBy})` : "";
  let first: string;
  switch (p.channel) {
    case "web":
      first = page ? `Soubor ${name} přišel${when} z internetu ze stránky ${page}${via}.` : `Soubor ${name} přišel${when} z internetu${via}.`;
      break;
    case "email":
      first = p.emailFrom ? `Soubor ${name} přišel${when} jako příloha e-mailu od ${p.emailFrom}.` : `Soubor ${name} přišel${when} jako příloha e-mailu.`;
      break;
    case "airDrop":
      first = `Soubor ${name} přišel${when} přes AirDrop.`;
      break;
    case "messages":
      first = `Soubor ${name} přišel${when} ve Zprávách.`;
      break;
    case "externalDrive":
      first = `Soubor ${name} je na externím disku.`;
      break;
    default:
      first = `Odkud se soubor ${name} vzal, systém nezaznamenal.`;
  }
  const speed =
    arrived !== null && story.detectedAtMs >= arrived && story.detectedAtMs - arrived < 30 * 86_400_000
      ? ` za ${shortDuration(story.detectedAtMs - arrived)}`
      : ` ${formatDateTime(story.detectedAtMs)}`;
  const second = {
    quarantined: outcome.type === "quarantined" && outcome.processTerminated
      ? `AntiShield ho${speed} zachytil, program ukončil a izoloval v karanténě.`
      : `AntiShield ho${speed} zachytil a izoloval v karanténě.`,
    reported: `AntiShield ho${speed} zachytil a čeká na vaše rozhodnutí.`,
    failed: `AntiShield ho${speed} zachytil, ale izolace se nepovedla.`,
  }[outcome.type];
  const test = finding.testOnly ? "Testovací soubor, ne skutečná hrozba. " : "";
  return `${test}${first} ${second}`;
}

/** Doporučení podle druhu hrozby (z názvu pravidla) a stavu. */
export function storyAdvice(story: Story): string[] {
  const { finding, outcome } = story;
  if (finding.testOnly) return ["Nic nehrozí: testovací soubor jen ověřil, že ochrana zasahuje."];
  const rule = finding.ruleName.toLowerCase();
  const advice: string[] = [];
  if (outcome.type !== "quarantined") advice.push("Vyčistěte nález: přesune se do karantény, odkud ho jde obnovit.");
  if (/steal|amos|atomic|poseidon|cuckoo|banshee|password|keychain/.test(rule)) {
    advice.push("Změňte hesla uložená v prohlížeči a u důležitých účtů zapněte dvoufázové ověření.");
    advice.push("Pokud máte krypto peněženku, převeďte prostředky do nové.");
  } else if (/ransom/.test(rule)) {
    advice.push("Zkontrolujte, že máte aktuální zálohu (Time Machine), a výkupné neplaťte.");
  } else if (/adware|adload|pirrit|genieo|hijack|pup/.test(rule)) {
    advice.push("Projděte rozšíření prohlížeče a domovskou stránku a odeberte, co neznáte.");
  } else if (/backdoor|\brat\b|trojan|dropper|loader|downloader/.test(rule)) {
    advice.push("Spusťte úplnou kontrolu a změňte hesla k důležitým účtům.");
  } else if (/miner|coin/.test(rule)) {
    advice.push("Zkontrolujte vytížení procesoru v Monitoru aktivity.");
  } else {
    advice.push("Spusťte úplnou kontrolu, ať víte, že nic dalšího nezůstalo.");
  }
  if (story.provenance.channel === "email") {
    advice.push("Odesílateli dejte vědět jinou cestou; jeho schránka může být napadená.");
  } else if (story.provenance.channel === "web") {
    advice.push("Ze stejné stránky nic dalšího nestahujte.");
  }
  return advice;
}

/** Krátký časový údaj pro krok: dnes jen čas, jinak datum a čas. */
export function stepTime(ms: number | null, now = Date.now()): string | null {
  if (ms === null) return null;
  const sameDay = new Date(ms).toDateString() === new Date(now).toDateString();
  return sameDay ? formatTime(ms) : formatDateTime(ms);
}

/** Příběh k nálezu (stejný soubor a obsah), pokud existuje. */
export function storyFor(stories: Story[], path: string, sha256?: string): Story | undefined {
  return stories.find((s) => s.finding.path === path && (!sha256 || s.finding.sha256 === sha256));
}
