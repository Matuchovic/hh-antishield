// Firemní správa: texty a výpočty pro rozhraní (bez volání backendu).
import { CATEGORIES, CATEGORY_ORDER, diskTone, memoryTone, uptimeText } from "./care";
import { describeAuditEvent, formatBytes, formatCount, formatTime } from "./format";
import type {
  CleanCategory,
  FleetAction,
  FleetCommand,
  FleetCommandKind,
  FleetCommandOptions,
  FleetCommandState,
  FleetDevice,
  FleetEvent,
  FleetPolicy,
  FleetReport,
  FleetSecurity,
  FleetShare,
} from "./types";

export type FleetTone = "good" | "caution" | "alert";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const GB = 1_000_000_000;

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
  if (r.security?.filevault === false) issues.push({ tone: "caution", text: "Disk není šifrovaný" });
  if (r.security?.firewall === false) issues.push({ tone: "caution", text: "Firewall je vypnutý" });
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

// ---------- Zásady ----------

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

export function hasAction(policy: FleetPolicy, action: FleetAction): boolean {
  return policy.actions?.includes(action) ?? false;
}

export function shares(policy: FleetPolicy, scope: FleetShare): boolean {
  return policy.share?.includes(scope) ?? false;
}

/** Má Mac potvrzenou rozšířenou správu (aspoň něco navíc)? */
export function isExtended(policy: FleetPolicy): boolean {
  return (policy.actions?.length ?? 0) > 0 || (policy.share?.length ?? 0) > 0;
}

/** Nabízí firma víc, než Mac potvrdil? */
export function offersMore(offer: FleetPolicy, accepted: FleetPolicy): boolean {
  return (
    offer.auto.some((c) => !accepted.auto.includes(c)) ||
    offer.consent.some((c) => !accepted.consent.includes(c) && !accepted.auto.includes(c)) ||
    (offer.actions ?? []).some((a) => !hasAction(accepted, a)) ||
    (offer.share ?? []).some((s) => !shares(accepted, s))
  );
}

/** Poslední nabídka zásad a jak dopadla. */
export function policyOffer(device: FleetDevice): FleetCommand | null {
  return device.commands.find((c) => c.kind === "policy") ?? null;
}

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

export function categoryBytes(report: FleetReport | null, category: CleanCategory): { bytes: number; items: number } {
  const found = report?.cleanup?.categories.find((c) => c.category === category);
  return { bytes: found?.bytes ?? 0, items: found?.items ?? 0 };
}

/** Kolik uvolní hloubková údržba hned (bez souhlasu uživatele). */
export function deepNowBytes(device: FleetDevice): number {
  const deep = device.report?.cleanup?.deep;
  if (deep && hasAction(device.policy, "deepClean")) return deep.nowBytes;
  return reclaimable(device.report, device.policy, "auto");
}

/** Výčet kategorií malými písmeny: „mezipaměti aplikací, staré protokoly a Koš“ (Koš je název složky). */
export function categoryList(categories: CleanCategory[]): string {
  const names = CATEGORY_ORDER.filter((c) => categories.includes(c)).map((c) =>
    c === "trash" ? CATEGORIES[c].label : CATEGORIES[c].label.toLowerCase(),
  );
  if (names.length <= 1) return names[0] ?? "";
  return `${names.slice(0, -1).join(", ")} a ${names[names.length - 1]}`;
}

// ---------- Příkazy ----------

export const IN_PROGRESS: FleetCommandState[] = ["queued", "delivered", "running", "awaitingConsent"];

export function commandInProgress(command: FleetCommand | undefined): boolean {
  return command !== undefined && IN_PROGRESS.includes(command.state);
}

/** Běží na Macu příkaz daného druhu? */
export function pending(device: FleetDevice, kind: FleetCommandKind): FleetCommand | null {
  return device.commands.find((c) => c.kind === kind && commandInProgress(c)) ?? null;
}

export function commandTitle(command: FleetCommand, policy: FleetPolicy): string {
  switch (command.kind) {
    case "scan":
      return command.full ? "Úplná kontrola na dálku" : "Kontrola na dálku";
    case "isolate":
      return "Izolace hrozeb";
    case "cleanup":
      if (command.deep) return "Hloubková údržba";
      return command.categories.some((c) => policyRule(policy, c) === "consent") ? "Žádost o úklid" : "Úklid na dálku";
    case "restart":
      return "Žádost o restart";
    case "quitApps":
      return "Ukončení aplikací";
    case "update":
      return "Aktualizace AntiShieldu a pravidel";
    case "deleteQuarantine":
      return "Vysypání karantény";
    case "policy":
      return "Žádost o rozšířenou správu";
  }
}

const RUNNING_TEXT: Record<FleetCommandKind, string> = {
  cleanup: "Uklízí…",
  scan: "Kontroluje…",
  isolate: "Izoluje…",
  restart: "Žádá o restart…",
  quitApps: "Ukončuje aplikace…",
  update: "Aktualizuje…",
  deleteQuarantine: "Maže z karantény…",
  policy: "Předává žádost…",
};

const DECLINED_TEXT: Record<FleetCommandKind, string> = {
  cleanup: "Uživatel úklid odmítl",
  scan: "Odmítnuto",
  isolate: "Odmítnuto",
  restart: "Uživatel restart odmítl",
  quitApps: "Uživatel aplikace nechal běžet",
  update: "Odmítnuto",
  deleteQuarantine: "Odmítnuto",
  policy: "Uživatel rozšířenou správu odmítl",
};

export function commandStatus(command: FleetCommand): { tone: FleetTone | "busy"; text: string } {
  switch (command.state) {
    case "queued":
      return { tone: "busy", text: "Čeká, až se Mac připojí" };
    case "delivered":
      return { tone: "busy", text: "Mac příkaz převzal" };
    case "running":
      return { tone: "busy", text: RUNNING_TEXT[command.kind] };
    case "awaitingConsent":
      if (command.untilMs) return { tone: "busy", text: `Uživatel odložil do ${formatTime(command.untilMs)}` };
      return { tone: "busy", text: "Čeká na souhlas uživatele" };
    case "declined":
      return { tone: "caution", text: DECLINED_TEXT[command.kind] };
    case "expired":
      return { tone: "caution", text: "Vypršelo bez odpovědi" };
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
        case "restart":
          return { tone: "good", text: "Mac se restartuje" };
        case "quitApps":
          return command.count
            ? { tone: "good", text: `Ukončeno ${command.count} z ${command.targets.length}` }
            : { tone: "good", text: "Aplikace neběžely" };
        case "update":
          return command.note
            ? { tone: "good", text: `Instaluje se ${command.note}` }
            : { tone: "good", text: "Aktuální" };
        case "deleteQuarantine":
          return { tone: "good", text: `Smazáno ${command.count} z ${command.targets.length}` };
        case "policy":
          return { tone: "good", text: "Uživatel souhlasil" };
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

export function fleetTotals(devices: FleetDevice[], latestVersion: string, now = Date.now()): FleetTotals {
  const active = devices.filter((d) => !d.left);
  const tones = active.map((d) => deviceTone(d, latestVersion, now));
  return {
    devices: active.length,
    online: active.filter((d) => isOnline(d, now)).length,
    watched: active.filter((d) => d.report && (d.report.protection === "monitored" || d.report.protection === "protected"))
      .length,
    threats: active.reduce((sum, d) => sum + activeThreats(d.report), 0),
    autoBytes: active.reduce((sum, d) => sum + deepNowBytes(d), 0),
    consentBytes: active.reduce((sum, d) => sum + reclaimable(d.report, d.policy, "consent"), 0),
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

// ---------- Detail Macu ----------

/** Podíl procesoru z promile: 123 → „12,3 %“. */
export function cpuText(permille: number): string {
  const value = permille / 10;
  return `${value.toLocaleString("cs-CZ", { maximumFractionDigits: value >= 10 ? 0 : 1 })} %`;
}

export type CheckState = "on" | "off" | "unknown";

export interface SecurityCheck {
  id: string;
  title: string;
  state: CheckState;
  /** Krátký stav do štítku: „Zapnuto“, „Čeká“, „Stará“… */
  label: string;
  /** Problém jednou větou, když ochrana chybí: „Firewall je vypnutý“. */
  offTitle: string;
  /** Co to znamená, když je ochrana v pořádku / vypnutá. */
  detail: string;
  /** Jak to na Macu zapnout (na dálku AntiShield ochrany systému nemění). */
  advice: string;
  /** Vážnost, když je vypnutá. */
  weight: FleetTone;
}

function state(value: boolean | null | undefined): CheckState {
  return value === true ? "on" : value === false ? "off" : "unknown";
}

function stateLabel(s: CheckState, on = "Zapnuto", off = "Vypnuto"): string {
  return s === "on" ? on : s === "off" ? off : "Nezjištěno";
}

/** „Čeká 1 aktualizace“, „Čekají 3 aktualizace“, „Čeká 5 aktualizací“. */
function waitingUpdates(n: number): string {
  return n <= 1 ? "Čeká 1 aktualizace" : n <= 4 ? `Čekají ${n} aktualizace` : `Čeká ${n} aktualizací`;
}

/** Ochrany systému z podrobností Macu, od nejdůležitější. */
export function securityChecks(security: FleetSecurity, now = Date.now()): SecurityCheck[] {
  const updates = security.osUpdates;
  const backup = security.backup;
  const backupState: CheckState = !backup
    ? "unknown"
    : !backup.configured || backup.lastMs === null || now - backup.lastMs > 7 * DAY
      ? "off"
      : "on";
  const filevault = state(security.filevault);
  const firewall = state(security.firewall);
  const sip = state(security.sip);
  const gatekeeper = state(security.gatekeeper);
  const updatesState: CheckState = updates === null ? "unknown" : updates.length ? "off" : "on";
  const autoUpdates = state(security.autoUpdates);
  const fullDiskAccess = state(security.fullDiskAccess);
  return [
    {
      id: "filevault",
      title: "Šifrování disku FileVault",
      state: filevault,
      label: stateLabel(filevault),
      offTitle: "Disk není šifrovaný (FileVault)",
      detail: "Data jsou v bezpečí, i když se Mac ztratí nebo ho někdo ukradne.",
      advice: "Na Macu: Nastavení systému → Soukromí a zabezpečení → FileVault.",
      weight: "alert",
    },
    {
      id: "firewall",
      title: "Firewall",
      state: firewall,
      label: stateLabel(firewall),
      offTitle: "Firewall je vypnutý",
      detail:
        security.stealth === true
          ? "Blokuje nevyžádaná příchozí spojení; neviditelný režim je zapnutý."
          : "Blokuje nevyžádaná příchozí spojení.",
      advice: "Na Macu: Nastavení systému → Síť → Firewall.",
      weight: "caution",
    },
    {
      id: "sip",
      title: "Ochrana integrity systému (SIP)",
      state: sip,
      label: stateLabel(sip),
      offTitle: "Ochrana integrity systému je vypnutá",
      detail: "Brání změnám systémových souborů i s právy správce.",
      advice: "Zapíná se v režimu obnovy příkazem csrutil enable.",
      weight: "alert",
    },
    {
      id: "gatekeeper",
      title: "Gatekeeper",
      state: gatekeeper,
      label: stateLabel(gatekeeper),
      offTitle: "Gatekeeper je vypnutý",
      detail: "Ověřuje aplikace stažené z internetu před spuštěním.",
      advice: "Na Macu: Nastavení systému → Soukromí a zabezpečení.",
      weight: "alert",
    },
    {
      id: "updates",
      title: "Aktualizace macOS",
      state: updatesState,
      label: stateLabel(updatesState, "Aktuální", "Čeká"),
      offTitle: updates && updates.length > 1 ? `${waitingUpdates(updates.length)} macOS` : "Čeká aktualizace macOS",
      detail:
        updates === null
          ? "Seznam čekajících aktualizací nejde zjistit."
          : updates.length
            ? `${waitingUpdates(updates.length)}: ${updates.map((u) => u.title).join(", ")}.`
            : "Systém je aktuální.",
      advice: "Na Macu: Nastavení systému → Obecné → Aktualizace softwaru.",
      weight: "caution",
    },
    {
      id: "autoUpdates",
      title: "Automatické bezpečnostní aktualizace",
      state: autoUpdates,
      label: stateLabel(autoUpdates),
      offTitle: "Automatické bezpečnostní aktualizace jsou vypnuté",
      detail: "Bezpečnostní opravy a definice XProtect se instalují samy.",
      advice: "Na Macu: Aktualizace softwaru → Automatické aktualizace.",
      weight: "caution",
    },
    {
      id: "backup",
      title: "Záloha Time Machine",
      state: backupState,
      label: stateLabel(
        backupState,
        "Aktuální",
        !backup?.configured ? "Nenastavená" : backup.lastMs === null ? "Neproběhla" : "Stará",
      ),
      offTitle: !backup?.configured
        ? "Mac se nezálohuje"
        : backup.lastMs === null
          ? "Záloha ještě neproběhla"
          : `Poslední záloha proběhla ${agoText(backup.lastMs, now)}`,
      detail: !backup
        ? "Stav zálohy nejde zjistit."
        : !backup.configured
          ? "Time Machine nemá nastavený disk pro zálohy."
          : backup.lastMs === null
            ? "Záloha je nastavená, ale ještě neproběhla."
            : `Poslední záloha ${agoText(backup.lastMs, now)}.`,
      advice: "Na Macu: Nastavení systému → Obecné → Time Machine.",
      weight: "caution",
    },
    {
      id: "fullDiskAccess",
      title: "Plný přístup AntiShieldu k disku",
      state: fullDiskAccess,
      label: stateLabel(fullDiskAccess, "Povolen", "Chybí"),
      offTitle: "AntiShield nemá plný přístup k disku",
      detail: "Bez něj AntiShield nehlídá chráněné složky (Pošta, Zprávy, Koš).",
      advice: "Na Macu: Nastavení systému → Soukromí a zabezpečení → Plný přístup k disku.",
      weight: "caution",
    },
  ];
}

export interface Health {
  /** 0–100 */
  score: number;
  label: string;
  tone: FleetTone;
  /** Co skóre snižuje, od nejvíc. */
  factors: { text: string; points: number }[];
  /** Mac neposílá stav zabezpečení: skóre je jen ze základních údajů. */
  partial: boolean;
}

/** Celkový stav Macu jako číslo: srážky za zjištěné problémy (jen to, co Mac poslal). */
export function deviceHealth(device: FleetDevice, latestVersion: string, now = Date.now()): Health {
  const r = device.report;
  const factors: { text: string; points: number }[] = [];
  const add = (points: number, text: string) => factors.push({ text, points });
  if (!r) {
    return {
      score: 0,
      label: "Bez zprávy",
      tone: "caution",
      factors: [{ text: "Mac zatím neposlal svůj stav", points: 100 }],
      partial: true,
    };
  }
  const threats = activeThreats(r);
  if (threats) add(40, formatCount(threats, "hrozba čeká na zásah", "hrozby čekají na zásah", "hrozeb čeká na zásah"));
  if (r.protection === "notReady") add(30, "Kontrola na Macu nefunguje");
  else if (r.protection === "manualScanOnly") add(12, "Hlídání je omezené");
  const disk = diskTone(r.disk);
  if (disk === "alert") add(18, "Dochází místo na disku");
  else if (disk === "caution") add(8, "Málo místa na disku");
  const memory = memoryTone({ ...r.memory, swapUsed: 0 });
  if (memory === "alert") add(10, "Kriticky málo paměti");
  else if (memory === "caution") add(5, "Paměti začíná být málo");
  if (r.security) {
    for (const check of securityChecks(r.security, now)) {
      if (check.state !== "off") continue;
      add(check.weight === "alert" ? 12 : 5, check.offTitle);
    }
  }
  const battery = r.hardware?.battery;
  if (battery?.service) add(5, "Baterie potřebuje servis");
  if (r.uptimeSecs > 14 * 86_400) add(4, `Bez restartu ${uptimeText(r.uptimeSecs)}`);
  if (compareVersions(r.appVersion, latestVersion) < 0) add(4, `Starší AntiShield ${r.appVersion}`);
  if (r.rulesCheckedAtMs !== null && now - r.rulesCheckedAtMs > 3 * DAY) add(5, "Pravidla se dlouho neaktualizovala");
  factors.sort((a, b) => b.points - a.points);
  const score = Math.max(0, 100 - factors.reduce((sum, f) => sum + f.points, 0));
  const tone: FleetTone = threats || r.protection === "notReady" || score < 60 ? "alert" : score < 85 ? "caution" : "good";
  // Bez stavu zabezpečení nejde říct „výborný“: FileVault, firewall ani aktualizace nejsou vidět.
  const partial = !r.security;
  const label =
    score >= 85 && partial
      ? "Ze základních údajů"
      : score >= 95
        ? "Výborný stav"
        : score >= 85
          ? "Dobrý stav"
          : score >= 60
            ? "Chce pozornost"
            : "Vážné problémy";
  return { score, label, tone, factors, partial };
}

export interface RecAction {
  label: string;
  kind: FleetCommandKind;
  categories?: CleanCategory[];
  options?: FleetCommandOptions;
}

export interface Recommendation {
  id: string;
  tone: FleetTone;
  title: string;
  detail: string;
  action?: RecAction;
  /** Záložka s podrobnostmi. */
  tab?: DeviceTab;
}

export type DeviceTab = "overview" | "care" | "security" | "performance" | "threats" | "hardware" | "history";

/** Co by správce měl udělat, od nejdůležitějšího; akce jen ty, které Mac dovoluje. */
export function recommendations(device: FleetDevice, latestVersion: string, now = Date.now()): Recommendation[] {
  const r = device.report;
  if (!r || device.left) return [];
  const p = device.policy;
  const recs: Recommendation[] = [];
  const threats = activeThreats(r);
  if (threats) {
    recs.push({
      id: "threats",
      tone: "alert",
      title: `${formatCount(threats, "hrozba čeká", "hrozby čekají", "hrozeb čeká")} na zásah`,
      detail: "Izolace přesune soubory do karantény, odkud je jde obnovit.",
      action: { label: "Izolovat", kind: "isolate" },
      tab: "threats",
    });
  }
  if (r.protection === "notReady") {
    recs.push({
      id: "protection",
      tone: "alert",
      title: "Kontrola na Macu nefunguje",
      detail: "AntiShield na Macu nemůže kontrolovat soubory. Uživatel by měl aplikaci otevřít.",
    });
  }
  const disk = diskTone(r.disk);
  const deepBytes = deepNowBytes(device);
  if (r.disk && disk !== "good") {
    recs.push({
      id: "disk",
      tone: disk,
      title: `Na disku zbývá ${formatBytes(r.disk.free)}`,
      detail: deepBytes ? `Údržba hned uvolní ${formatBytes(deepBytes)}.` : "Velké soubory a Koš uvolní uživatel.",
      action: deepBytes
        ? {
            label: "Uvolnit místo",
            kind: "cleanup",
            categories: p.auto,
            options: hasAction(p, "deepClean") ? { deep: true } : undefined,
          }
        : undefined,
      tab: "care",
    });
  } else if (deepBytes > 2 * GB) {
    recs.push({
      id: "clean",
      tone: "good",
      title: `Jde uvolnit ${formatBytes(deepBytes)}`,
      detail: "Mezipaměti, protokoly a vývojářská data. Uživatel dostane oznámení.",
      action: {
        label: "Uklidit",
        kind: "cleanup",
        categories: p.auto,
        options: hasAction(p, "deepClean") ? { deep: true } : undefined,
      },
      tab: "care",
    });
  }
  if (r.security) {
    for (const check of securityChecks(r.security, now)) {
      if (check.state !== "off" || check.id === "fullDiskAccess") continue;
      recs.push({
        id: `security-${check.id}`,
        tone: check.weight,
        title: check.offTitle,
        detail: check.id === "updates" ? check.detail : check.advice,
        tab: "security",
      });
    }
  }
  const appOld = compareVersions(r.appVersion, latestVersion) < 0;
  if (appOld || (r.rulesCheckedAtMs !== null && now - r.rulesCheckedAtMs > 3 * DAY)) {
    const canUpdate = hasAction(p, "updates");
    recs.push({
      id: "update",
      tone: "caution",
      title: appOld ? `AntiShield ${r.appVersion} je starší` : "Pravidla jsou stará",
      detail: appOld
        ? `Nejnovější verze je ${latestVersion}. ${canUpdate ? "Aktualizace se ověří podpisem a aplikace se sama restartuje." : "Na dálku ji jde spustit s rozšířenou správou."}`
        : `Naposledy ověřena ${agoText(r.rulesCheckedAtMs ?? now, now)}. ${canUpdate ? "Aktualizace stáhne nová a ověří jejich podpis." : "Mac je stáhne sám, jakmile bude online."}`,
      action: canUpdate ? { label: "Aktualizovat", kind: "update" } : undefined,
    });
  }
  if (r.uptimeSecs > 7 * 86_400) {
    const canRestart = hasAction(p, "restart");
    recs.push({
      id: "restart",
      tone: r.uptimeSecs > 14 * 86_400 ? "caution" : "good",
      title: `Mac běží ${uptimeText(r.uptimeSecs)} bez restartu`,
      detail: canRestart
        ? "Restart uvolní paměť a dokončí aktualizace. Uživatel ho může odložit."
        : "Restart uvolní paměť a dokončí aktualizace. Požádat o něj na dálku jde s rozšířenou správou.",
      action: canRestart ? { label: "Požádat o restart", kind: "restart" } : undefined,
    });
  }
  const battery = r.hardware?.battery;
  if (battery?.service) {
    recs.push({
      id: "battery",
      tone: "caution",
      title: "Baterie potřebuje servis",
      detail: `Kapacita ${battery.healthPct ?? "?"} % po ${battery.cycles} cyklech. Domluvte výměnu.`,
      tab: "hardware",
    });
  }
  const order = { alert: 0, caution: 1, good: 2 } as const;
  return recs.sort((a, b) => order[a.tone] - order[b.tone]);
}

/** Událost z časové osy Macu česky (stejné texty jako Události na Macu). */
export function describeFleetEvent(event: FleetEvent): { title: string; detail: string } {
  return describeAuditEvent({ seq: 0, tsMs: event.atMs, kind: event.kind, data: event.data });
}
