// Firemní správa: texty a výpočty pro rozhraní (bez volání backendu).
import { CATEGORIES, CATEGORY_ORDER, diskTone } from "./care";
import { formatBytes, formatCount } from "./format";
import type {
  CleanCategory,
  FleetCommand,
  FleetCommandState,
  FleetDevice,
  FleetPolicy,
  FleetReport,
} from "./types";

export type FleetTone = "good" | "caution" | "alert";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** Mac se schránce hlásí zhruba každou minutu; po třech minutách ticha je offline. */
export const ONLINE_WINDOW_MS = 3 * MINUTE;

export function isOnline(device: FleetDevice, now = Date.now()): boolean {
  return !device.left && device.lastSeenMs !== null && now - device.lastSeenMs < ONLINE_WINDOW_MS;
}

/** „před 5 min“, „před 3 h“, „před 2 dny“. */
export function agoText(ms: number, now = Date.now()): string {
  const diff = Math.max(0, now - ms);
  if (diff < MINUTE) return "právě teď";
  if (diff < HOUR) return `před ${Math.round(diff / MINUTE)} min`;
  if (diff < DAY) return `před ${Math.round(diff / HOUR)} h`;
  const days = Math.round(diff / DAY);
  return `před ${days} ${days === 1 ? "dnem" : "dny"}`;
}

export function connectionText(device: FleetDevice, now = Date.now()): string {
  if (device.left) return "Odpojený uživatelem";
  if (device.lastSeenMs === null) return "Ještě se nepřipojil";
  if (isOnline(device, now)) return "Online";
  return `Offline, naposledy ${agoText(device.lastSeenMs, now)}`;
}

/** Porovná verze „0.6.0“ a „0.7.0“ (záporné číslo = a je starší). */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.-]/).map((p) => Number.parseInt(p, 10) || 0);
  const pb = b.split(/[.-]/).map((p) => Number.parseInt(p, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

export interface Issue {
  tone: FleetTone;
  text: string;
}

export function activeThreats(report: FleetReport | null): number {
  return report ? report.threats.filter((t) => !t.quarantined).length : 0;
}

/** Co na Macu potřebuje pozornost, od nejvážnějšího. */
export function deviceIssues(device: FleetDevice, latestVersion: string, now = Date.now()): Issue[] {
  if (device.left) return [{ tone: "caution", text: "Uživatel Mac od firmy odpojil" }];
  const r = device.report;
  if (!r) return [{ tone: "caution", text: "Mac zatím neposlal svůj stav" }];
  const issues: Issue[] = [];
  const threats = activeThreats(r);
  if (threats) {
    issues.push({ tone: "alert", text: `${formatCount(threats, "hrozba čeká", "hrozby čekají", "hrozeb čeká")} na zásah` });
  }
  if (r.protection === "notReady") issues.push({ tone: "alert", text: "Kontrola na Macu nefunguje" });
  else if (r.protection === "manualScanOnly") issues.push({ tone: "caution", text: "Hlídání je omezené" });
  const disk = diskTone(r.disk);
  if (disk === "alert") issues.push({ tone: "alert", text: "Dochází místo na disku" });
  else if (disk === "caution") issues.push({ tone: "caution", text: "Málo místa na disku" });
  if (compareVersions(r.appVersion, latestVersion) < 0) {
    issues.push({ tone: "caution", text: `Starší AntiShield ${r.appVersion}` });
  }
  if (r.rulesCheckedAtMs !== null && now - r.rulesCheckedAtMs > 3 * DAY) {
    issues.push({ tone: "caution", text: "Pravidla se dlouho neaktualizovala" });
  }
  if (device.lastSeenMs !== null && now - device.lastSeenMs > 7 * DAY) {
    issues.push({ tone: "caution", text: "Přes týden bez spojení" });
  }
  return issues.sort((a, b) => (a.tone === b.tone ? 0 : a.tone === "alert" ? -1 : 1));
}

export function deviceTone(device: FleetDevice, latestVersion: string, now = Date.now()): FleetTone {
  return deviceIssues(device, latestVersion, now)[0]?.tone ?? "good";
}

export type PolicyRule = "auto" | "consent" | "never";

export function policyRule(policy: FleetPolicy, category: CleanCategory): PolicyRule {
  if (policy.auto.includes(category)) return "auto";
  if (policy.consent.includes(category)) return "consent";
  return "never";
}

export const POLICY_TEXT: Record<PolicyRule, string> = {
  auto: "Hned",
  consent: "Se souhlasem",
  never: "Jen uživatel",
};

/** Velikost kategorií s daným pravidlem v poslední zprávě Macu. */
export function reclaimable(report: FleetReport | null, policy: FleetPolicy, rule: PolicyRule): number {
  if (!report?.cleanup) return 0;
  return report.cleanup.categories
    .filter((c) => policyRule(policy, c.category) === rule)
    .reduce((sum, c) => sum + c.bytes, 0);
}

/** Kategorie s daným pravidlem, které na Macu opravdu něco obsahují. */
export function categoriesWith(report: FleetReport | null, policy: FleetPolicy, rule: PolicyRule): CleanCategory[] {
  if (!report?.cleanup) return [];
  return CATEGORY_ORDER.filter((cat) =>
    report.cleanup?.categories.some((c) => c.category === cat && c.bytes > 0 && policyRule(policy, cat) === rule),
  );
}

/** Výčet kategorií malými písmeny: „mezipaměti aplikací, staré protokoly a …“. */
export function categoryList(categories: CleanCategory[]): string {
  const names = CATEGORY_ORDER.filter((c) => categories.includes(c)).map((c) => CATEGORIES[c].label.toLowerCase());
  if (names.length <= 1) return names[0] ?? "";
  return `${names.slice(0, -1).join(", ")} a ${names[names.length - 1]}`;
}

export const IN_PROGRESS: FleetCommandState[] = ["queued", "delivered", "running", "awaitingConsent"];

export function commandInProgress(command: FleetCommand | undefined): boolean {
  return command !== undefined && IN_PROGRESS.includes(command.state);
}

export function commandTitle(command: FleetCommand, policy: FleetPolicy): string {
  switch (command.kind) {
    case "scan":
      return "Kontrola na dálku";
    case "isolate":
      return "Izolace hrozeb";
    case "cleanup":
      return command.categories.some((c) => policyRule(policy, c) === "consent") ? "Žádost o úklid" : "Úklid na dálku";
  }
}

export function commandStatus(command: FleetCommand): { tone: FleetTone | "busy"; text: string } {
  switch (command.state) {
    case "queued":
      return { tone: "busy", text: "Čeká, až se Mac připojí" };
    case "delivered":
      return { tone: "busy", text: "Mac příkaz převzal" };
    case "running":
      return {
        tone: "busy",
        text: command.kind === "cleanup" ? "Uklízí…" : command.kind === "scan" ? "Kontroluje…" : "Izoluje…",
      };
    case "awaitingConsent":
      return { tone: "busy", text: "Čeká na souhlas uživatele" };
    case "declined":
      return { tone: "caution", text: "Uživatel úklid odmítl" };
    case "expired":
      return { tone: "caution", text: "Vypršelo, Mac se nepřipojil" };
    case "failed":
      return { tone: "alert", text: "Nepovedlo se" };
    case "done":
      switch (command.kind) {
        case "cleanup": {
          const total = command.freedBytes + command.trashedBytes;
          if (total === 0) return { tone: "good", text: "Nebylo co uklidit" };
          if (command.freedBytes === 0) return { tone: "good", text: `${formatBytes(command.trashedBytes)} v Koši` };
          return {
            tone: "good",
            text:
              command.trashedBytes > 0
                ? `Uvolněno ${formatBytes(command.freedBytes)}, ${formatBytes(command.trashedBytes)} v Koši`
                : `Uvolněno ${formatBytes(command.freedBytes)}`,
          };
        }
        case "scan":
          return command.threats
            ? { tone: "alert", text: formatCount(command.threats, "nález", "nálezy", "nálezů") }
            : { tone: "good", text: `${formatCount(command.files, "soubor", "soubory", "souborů")}, bez nálezu` };
        case "isolate":
          return { tone: "good", text: `Izolováno: ${command.threats}` };
      }
  }
}

/** Iniciály pro značku Macu: „Petr Novák“ → „PN“. */
export function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  const letters = parts.length > 1 ? [parts[0], parts[parts.length - 1]] : [parts[0] ?? "?"];
  return letters.map((p) => (p ?? "").slice(0, 1).toUpperCase()).join("");
}

/** Krátké jméno pro mapu: „Petr Novák“ → „Petr N.“. */
export function shortName(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length < 2) return parts[0] ?? name;
  return `${parts[0]} ${(parts[parts.length - 1] ?? "").slice(0, 1)}.`;
}

export interface FleetTotals {
  devices: number;
  online: number;
  watched: number;
  threats: number;
  autoBytes: number;
  consentBytes: number;
  attention: number;
  tone: FleetTone;
}

export function fleetTotals(
  devices: FleetDevice[],
  policy: FleetPolicy,
  latestVersion: string,
  now = Date.now(),
): FleetTotals {
  const active = devices.filter((d) => !d.left);
  const tones = active.map((d) => deviceTone(d, latestVersion, now));
  return {
    devices: active.length,
    online: active.filter((d) => isOnline(d, now)).length,
    watched: active.filter((d) => d.report && (d.report.protection === "monitored" || d.report.protection === "protected"))
      .length,
    threats: active.reduce((sum, d) => sum + activeThreats(d.report), 0),
    autoBytes: active.reduce((sum, d) => sum + reclaimable(d.report, policy, "auto"), 0),
    consentBytes: active.reduce((sum, d) => sum + reclaimable(d.report, policy, "consent"), 0),
    attention: tones.filter((t) => t !== "good").length,
    tone: tones.includes("alert") ? "alert" : tones.includes("caution") ? "caution" : "good",
  };
}

export function fleetHeadline(totals: FleetTotals): string {
  if (totals.devices === 0) return "Zatím tu není žádný firemní Mac";
  if (totals.attention === 0) {
    return totals.devices === 1 ? "Mac je v pořádku" : "Všechny Macy jsou v pořádku";
  }
  const n = totals.attention;
  return `${n} ${n === 1 ? "Mac potřebuje" : n <= 4 ? "Macy potřebují" : "Maců potřebuje"} pozornost`;
}

/** Otisk klíče po čtveřicích: „7F3A 91C2 4B0E 5D11“. */
export function groupFingerprint(fingerprint: string): string {
  return fingerprint.replace(/\s+/g, "").toUpperCase().replace(/(.{4})(?=.)/g, "$1 ");
}
