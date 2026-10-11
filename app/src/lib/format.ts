// Texty rozhraní. Vše, co uživatel čte o stavu ochrany, vzniká tady z dat
// enginu, nikdy natvrdo v komponentách. Testy hlídají, že „chráněno“
// nevznikne bez běžící ochrany v reálném čase.
import type {
  AuditEvent,
  ComponentKind,
  ComponentState,
  ComponentStatus,
  ErrorDto,
  Evidence,
  Finding,
  ProtectionLevel,
  ScanOutcome,
  SkipReason,
} from "./types";

export const COMPONENT_LABELS: Record<ComponentKind, string> = {
  detectionEngine: "Detekční engine",
  rulePack: "Sada pravidel",
  auditLog: "Auditní log",
  onDemandScan: "Ruční kontrola",
  realTimeProtection: "Ochrana v reálném čase",
  webProtection: "Internetová ochrana",
  emailProtection: "Ochrana e-mailů",
  privacyProtection: "Ochrana soukromí",
  quarantine: "Karanténa",
  updates: "Aktualizace pravidel",
  systemCare: "System Care",
};

/** Komponenty, které tvoří ochranu; ostatní jsou servisní. */
export const SHIELD_LAYERS: ComponentKind[] = [
  "detectionEngine",
  "rulePack",
  "onDemandScan",
  "realTimeProtection",
  "webProtection",
  "emailProtection",
];

const REASONS: Record<string, string> = {
  "self-test has not run yet": "self-test zatím neproběhl",
  "rule pack has expired": "platnost sady pravidel vypršela",
  "audit log cannot be written": "do auditního logu nejde zapisovat",
  "rule pack signature is invalid": "podpis sady pravidel je neplatný",
  "a scan is already running": "kontrola už běží",
};

export function translateReason(reason: string): string {
  return REASONS[reason] ?? reason;
}

export function formatTime(ms: number): string {
  return new Date(ms).toLocaleTimeString("cs-CZ", { hour: "2-digit", minute: "2-digit" });
}

export function formatDateTime(ms: number): string {
  return new Date(ms).toLocaleString("cs-CZ", {
    day: "numeric",
    month: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function describeState(state: ComponentState): string {
  switch (state.type) {
    case "running":
      return `Běží, ověřeno v ${formatTime(state.verifiedAtMs)}`;
    case "notImplemented":
      return "Není ve verzi 0.1";
    case "disabled":
      return "Vypnuto";
    case "degraded":
      return `Omezeno: ${translateReason(state.reason)}`;
    case "failed":
      return `Selhalo: ${translateReason(state.reason)}`;
  }
}

export type Tone = "good" | "caution" | "alert" | "off";

export function stateTone(state: ComponentState): Tone {
  switch (state.type) {
    case "running":
      return "good";
    case "degraded":
      return "caution";
    case "failed":
      return "alert";
    default:
      return "off";
  }
}

export interface Headline {
  title: string;
  detail: string;
  tone: Tone;
}

/** Souhrnný nápis. „Chráněno“ jen při úrovni `protected` z enginu. */
export function headline(level: ProtectionLevel, components: ComponentStatus[]): Headline {
  const realtime = components.find((c) => c.kind === "realTimeProtection");
  const realtimeRunning = realtime?.state.type === "running";
  switch (level) {
    case "protected":
      return realtimeRunning
        ? { title: "Ochrana běží", detail: "Všechny ochranné vrstvy hlásí ověřený stav.", tone: "good" }
        : { title: "Stav nelze potvrdit", detail: "Engine hlásí ochranu bez běžící ochrany v reálném čase.", tone: "alert" };
    case "manualScanOnly":
      return {
        title: "Ruční kontrola je připravená",
        detail:
          "Ochrana v reálném čase zatím není součástí verze 0.1. Soubory se kontrolují jen tehdy, když je vyberete.",
        tone: "caution",
      };
    case "notReady": {
      const required: ComponentKind[] = ["detectionEngine", "rulePack", "onDemandScan"];
      let reason = "Engine se ještě neověřil.";
      for (const c of components) {
        if (required.includes(c.kind) && (c.state.type === "failed" || c.state.type === "degraded")) {
          reason = `${COMPONENT_LABELS[c.kind]}: ${translateReason(c.state.reason)}`;
          break;
        }
      }
      return { title: "Kontrola není připravená", detail: reason, tone: "alert" };
    }
  }
}

export const SKIP_LABELS: Record<SkipReason["type"], string> = {
  symlink: "Symbolický odkaz (nesledujeme ho)",
  notRegularFile: "Nejde o běžný soubor",
  tooLarge: "Soubor je větší než limit",
  notDownloaded: "Soubor není stažený z cloudu",
  otherVolume: "Jiný nebo síťový disk",
  permissionDenied: "Bez oprávnění ke čtení",
  notFound: "Soubor mezitím zmizel",
  timeout: "Čtení se zaseklo",
  readError: "Chyba při čtení",
  internalError: "Interní chyba enginu",
};

export function describeEvidence(evidence: Evidence, ruleId: string): string {
  switch (evidence.type) {
    case "sha256Match":
      return `SHA-256 celého souboru se přesně shoduje s indikátorem ${ruleId}.`;
    case "bytePattern":
      return `Soubor obsahuje vzor pravidla ${ruleId} na pozici ${evidence.offset} (${evidence.length} B).`;
    case "eicarStandard":
      return "Soubor odpovídá oficiální definici testovacího souboru EICAR.";
  }
}

export function findingNote(finding: Finding): string | null {
  const notes: string[] = [];
  if (finding.testOnly) notes.push("Testovací detekce, nejde o škodlivý software.");
  if (finding.changedDuringRead)
    notes.push("Soubor se během čtení změnil, nález nemusí odpovídat aktuálnímu obsahu.");
  return notes.length ? notes.join(" ") : null;
}

export function describeOutcome(outcome: ScanOutcome): string {
  switch (outcome.type) {
    case "completed":
      return "Kontrola dokončena";
    case "cancelled":
      return "Kontrola zrušena";
    case "failed":
      return `Kontrola selhala: ${outcome.reason}`;
  }
}

const ERRORS: Record<string, string> = {
  rule_pack_signature_invalid: "Podpis sady pravidel je neplatný. Engine pravidla odmítl a kontrolu nespustí.",
  rule_pack_unknown_key: "Sada pravidel je podepsaná neznámým klíčem. Engine ji odmítl.",
  rule_pack_malformed: "Sada pravidel je poškozená. Engine ji odmítl.",
  rule_pack_incompatible: "Sada pravidel vyžaduje novější verzi aplikace.",
  rule_pack_too_large: "Sada pravidel je příliš velká. Engine ji odmítl.",
  scan_already_running: "Kontrola už běží. Počkejte na její konec nebo ji zrušte.",
  audit: "Auditní log není dostupný.",
  update: "Aktualizaci se nepodařilo stáhnout nebo ověřit. Zkuste to později.",
  scan_running: "Počkejte na konec kontroly, pak aktualizujte.",
  no_update: "Žádná aktualizace není připravená. Zkontrolujte aktualizace znovu.",
};

export function describeError(error: ErrorDto): string {
  return ERRORS[error.code] ?? error.message;
}

export function formatBytes(bytes: number): string {
  const units = ["B", "kB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit += 1;
  }
  const digits = unit === 0 || value >= 100 ? 0 : 1;
  return `${value.toLocaleString("cs-CZ", { maximumFractionDigits: digits })} ${units[unit]}`;
}

export function formatDuration(ms: number): string {
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes} min ${seconds % 60} s`;
}

export function formatCount(n: number, one: string, few: string, many: string): string {
  const word = n === 1 ? one : n >= 2 && n <= 4 ? few : many;
  return `${n.toLocaleString("cs-CZ")} ${word}`;
}

const AUDIT_KINDS: Record<string, string> = {
  engine_started: "Engine spuštěn",
  rule_pack_loaded: "Sada pravidel načtena a ověřena",
  rule_pack_rejected: "Sada pravidel odmítnuta",
  self_test: "Self-test",
  scan_started: "Kontrola zahájena",
  scan_finished: "Kontrola skončila",
  finding: "Nález",
  audit_integrity_issue: "Problém s integritou auditu",
};

export function describeAuditEvent(event: AuditEvent): { title: string; detail: string } {
  const title = AUDIT_KINDS[event.kind] ?? event.kind;
  const d = event.data;
  switch (event.kind) {
    case "self_test":
      return { title, detail: d.passed ? "prošel" : "selhal" };
    case "finding":
      return { title, detail: `${String(d.ruleId ?? "")} v ${String(d.path ?? "")}` };
    case "scan_started":
      return { title, detail: Array.isArray(d.roots) ? d.roots.join(", ") : "" };
    case "scan_finished": {
      const outcome = d.outcome as ScanOutcome | undefined;
      const files = Number(d.filesScanned ?? 0);
      const findings = Number(d.findings ?? 0);
      return {
        title,
        detail: `${outcome ? describeOutcome(outcome) : ""}: ${formatCount(files, "soubor", "soubory", "souborů")}, ${formatCount(findings, "nález", "nálezy", "nálezů")}`,
      };
    }
    case "rule_pack_loaded":
      return { title, detail: `${String(d.packId ?? "")} ${String(d.version ?? "")}` };
    case "rule_pack_rejected":
      return { title, detail: String(d.message ?? "") };
    case "engine_started":
      return { title, detail: `verze ${String(d.engineVersion ?? "")}` };
    default:
      return { title, detail: "" };
  }
}

/** "macos-aarch64" → "macOS Apple Silicon". */
export function platformName(platform: string): string {
  const [os = "", arch = ""] = platform.split("-");
  const osName = ({ macos: "macOS", windows: "Windows", linux: "Linux" } as Record<string, string>)[os] ?? os;
  const archName =
    arch === "aarch64" ? (os === "macos" ? "Apple Silicon" : "ARM64") : arch === "x86_64" ? (os === "macos" ? "Intel" : "x64") : arch;
  return `${osName} ${archName}`.trim();
}

export function formatDate(ms: number): string {
  return new Date(ms).toLocaleDateString("cs-CZ", { day: "numeric", month: "numeric", year: "numeric" });
}
