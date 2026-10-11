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
  FindingOrigin,
  ProtectionLevel,
  RuleSourceInfo,
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
  "folder watching is starting": "hlídání se spouští",
  "no watched folder exists": "žádná hlídaná složka neexistuje",
  "full disk access is required": "vyžaduje plný přístup k disku",
  "apple mail is not used": "Apple Mail se na tomto Macu nepoužívá",
  "mail folders are not watched": "složky Mailu se nehlídají",
  "the permission overview is starting": "přehled oprávnění se načítá",
  "the permission database could not be read": "databázi oprávnění nejde přečíst",
  "not available on this system": "na tomto systému zatím není",
  "no access to files in a watched folder": "systém nedovolil číst soubory v hlídané složce",
  "app is not installed in Applications":
    "ochrana na pozadí potřebuje aplikaci ve složce Aplikace; přetáhněte ji tam z DMG a spusťte odtud",
  "not running from an app bundle": "ochrana na pozadí funguje jen v nainstalované aplikaci",
  "background protection stopped after repeated crashes":
    "ochrana na pozadí se po opakovaných pádech zastavila; po zavření aplikace se zkusí spustit znovu",
  "rule updates have not run yet": "aktualizace pravidel ještě neproběhla",
  "rule updates are not published yet": "aktualizace pravidel zatím nejsou zveřejněné",
  "the engine is still starting": "engine se spouští",
  "quarantine storage is not writable": "do karantény nejde zapisovat",
};

export function translateReason(reason: string): string {
  return REASONS[reason] ?? reason;
}

/** První písmeno velké (důvody jsou psané jako pokračování věty). */
export function capitalize(text: string): string {
  return text.charAt(0).toLocaleUpperCase("cs-CZ") + text.slice(1);
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

function stateOf(components: ComponentStatus[], kind: ComponentKind): ComponentState | undefined {
  return components.find((c) => c.kind === kind)?.state;
}

/** Souhrnný nápis. „Chráněn“ jen při úrovni `protected`, „hlídaný“ při `monitored`. */
export function headline(
  level: ProtectionLevel,
  components: ComponentStatus[],
  device = "počítač",
): Headline {
  const realtime = stateOf(components, "realTimeProtection");
  const updates = stateOf(components, "updates");
  const realtimeRunning = realtime?.type === "running";
  const subject = device === "Mac" ? "Váš Mac je" : "Váš počítač je";
  switch (level) {
    case "protected":
      return realtimeRunning
        ? { title: `${subject} chráněn`, detail: "Všechny ochranné vrstvy hlásí ověřený stav.", tone: "good" }
        : { title: "Stav nelze potvrdit", detail: "Engine hlásí ochranu bez běžící ochrany v reálném čase.", tone: "alert" };
    case "monitored":
      return realtimeRunning
        ? {
            title: `${subject} hlídaný`,
            detail:
              "Nové soubory, spuštěné programy i položky po přihlášení se kontrolují automaticky a pravidla se aktualizují. Spuštění programu zatím předem neblokujeme.",
            tone: "good",
          }
        : { title: "Stav nelze potvrdit", detail: "Hlídání složek neběží.", tone: "alert" };
    case "manualScanOnly": {
      let detail = "Soubory se kontrolují, když je vyberete.";
      if (realtime?.type === "disabled") {
        detail = "Hlídání složek je vypnuté. Zapnete ho v Nastavení.";
      } else if (realtime?.type === "degraded" && realtime.reason === "no access to files in a watched folder") {
        detail = "Hlídání je omezené: systém nedovolil číst soubory v hlídané složce. Povolte přístup v Ochraně v reálném čase.";
      } else if (realtime?.type === "failed" || realtime?.type === "degraded") {
        detail = `Hlídání složek neběží: ${translateReason(realtime.reason)}.`;
      } else if (updates?.type === "disabled") {
        detail = "Hlídání běží, ale automatické aktualizace pravidel jsou vypnuté.";
      } else if (updates?.type === "degraded" || updates?.type === "failed") {
        detail = `Hlídání běží, čeká se na pravidla: ${translateReason(updates.reason)}.`;
      }
      return { title: "Ruční kontrola je připravená", detail, tone: "caution" };
    }
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
  timeout: "Kontrola souboru trvala příliš dlouho",
  readError: "Chyba při čtení",
  internalError: "Interní chyba enginu",
};

export function describeEvidence(evidence: Evidence, ruleId: string, sources: RuleSourceInfo[] = []): string {
  switch (evidence.type) {
    case "yaraMatch": {
      const source = sources.find((s) => s.id === evidence.source);
      const from = source ? ` ze sady ${source.name} (${source.license})` : "";
      const author = evidence.author ? `, autor ${evidence.author}` : "";
      return `Soubor splňuje pravidlo YARA ${evidence.rule}${from}${author}.`;
    }
    case "sha256Match":
      return `SHA-256 celého souboru se přesně shoduje s indikátorem ${ruleId}.`;
    case "bytePattern":
      return `Soubor obsahuje vzor pravidla ${ruleId} na pozici ${evidence.offset} (${evidence.length} B).`;
    case "eicarStandard":
      return "Soubor odpovídá oficiální definici testovacího souboru EICAR.";
  }
}

export function describeOrigin(origin: FindingOrigin | null): string | null {
  if (!origin) return null;
  return origin.type === "process"
    ? `Běžící proces ${origin.name} (PID ${origin.pid}). Vyčištění ho ukončí.`
    : `Spouští se po přihlášení (${origin.label || origin.location}). Vyčištění položku vypne.`;
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
  engine_starting: "Engine se ještě spouští, zkuste to za chvíli.",
  unknown_finding: "Tento nález už neexistuje. Spusťte kontrolu znovu.",
  file_changed: "Soubor se od kontroly změnil, proto se nepřesunul. Zkontrolujte ho znovu.",
  quarantine_item_not_found: "Položka v karanténě už neexistuje.",
  restore_conflict: "Na původním místě už je jiný soubor. Přesuňte ho a zkuste obnovu znovu.",
  rule_pack_rollback: "Nabídnutá sada pravidel je starší než nainstalovaná, proto se odmítla.",
  rule_pack_self_test: "Nová sada pravidel neprošla self-testem a nenainstalovala se.",
  rules_not_published: "Aktualizace pravidel zatím nejsou zveřejněné.",
  rules_download: "Pravidla se nepodařilo stáhnout. Zkontrolujte připojení k internetu.",
  rules_busy: "Aktualizace pravidel už probíhá.",
  invalid_settings: "Nastavení obsahuje neplatnou hodnotu.",
  autostart: "Spuštění po přihlášení se nepodařilo změnit.",
  no_targets: "Není co kontrolovat: žádná ze složek neexistuje.",
  update: "Aktualizaci se nepodařilo stáhnout nebo ověřit. Zkuste to později.",
  update_location:
    "Aktualizovat jde jen aplikaci ve složce Aplikace. Ukončete AntiShield, přetáhněte ho z DMG do Aplikací a spusťte odtud.",
  scan_running: "Počkejte na konec kontroly, pak aktualizujte.",
  no_update: "Žádná aktualizace není připravená. Zkontrolujte aktualizace znovu.",
  clean_running: "Hledání už běží.",
  clean_unknown: "Vybrané položky už v posledním hledání nejsou. Hledejte znovu.",
  no_home: "Domovskou složku nejde zjistit.",
  speed_unknown: "Údaje se mezitím změnily. Změřte stav znovu.",
  startup_system: "Položky pro celý systém se zapínají a vypínají v Nastavení systému.",
  quit_automation_denied:
    "macOS nedovolil aplikaci požádat o ukončení. Povolte to v Nastavení systému → Soukromí a zabezpečení → Automatizace, nebo ji ukončete sami (⌘Q).",
  quit_no_window: "Program nemá okno, které by šlo zavřít. Ukončete ho sami.",
  quit_protected: "Tento program AntiShield neukončuje.",
  quit_failed: "Aplikace požadavek na ukončení nepřijala. Ukončete ji sami (⌘Q).",
};

export function describeError(error: ErrorDto): string {
  const text = ERRORS[error.code] ?? error.message;
  // U aktualizace ukázat i technický důvod (pomáhá při podpoře).
  return error.code === "update" && error.message ? `${text} (${error.message})` : text;
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

/** Cesta k zobrazení: bez předpony `\\?\`, kterou Windows přidává ke kanonickým cestám. */
export function displayPath(path: string): string {
  if (path.startsWith("\\\\?\\UNC\\")) return `\\\\${path.slice(8)}`;
  if (path.startsWith("\\\\?\\")) return path.slice(4);
  return path;
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
  quarantined: "Přesunuto do karantény",
  quarantine_restored: "Obnoveno z karantény",
  quarantine_deleted: "Smazáno z karantény",
  quarantine_failed: "Přesun do karantény selhal",
  remediated: "Vyčištění",
  rule_pack_installed: "Nová sada pravidel nainstalována",
};

/** Problém s integritou auditu z technického popisu enginu. */
function describeIntegrityIssue(detail: string, sealed: boolean): string {
  const what = /chain broken|sequence jumps/.test(detail)
    ? "záznamy na sebe nenavazují (souběžný zápis nebo úprava)"
    : /truncated|not a valid record/.test(detail)
      ? "useknutý zápis, nejspíš po nečekaném vypnutí"
      : "část logu nejde přečíst";
  return capitalize(sealed ? `${what}; uzavřeno, zápis pokračuje v novém souboru` : what);
}

export function describeAuditEvent(event: AuditEvent): { title: string; detail: string } {
  const title = AUDIT_KINDS[event.kind] ?? event.kind;
  const d = event.data;
  switch (event.kind) {
    case "self_test":
      return { title, detail: d.passed ? "prošel" : "selhal" };
    case "finding":
      return { title, detail: `${String(d.ruleId ?? "")} v ${displayPath(String(d.path ?? ""))}` };
    case "scan_started":
      return { title, detail: Array.isArray(d.roots) ? d.roots.join(", ") : "" };
    case "scan_finished": {
      const outcome = d.outcome as ScanOutcome | undefined;
      const files = Number(d.filesScanned ?? 0);
      const findings = Number(d.findings ?? 0);
      return {
        title,
        detail: [
          outcome ? describeOutcome(outcome) : null,
          `${formatCount(files, "soubor", "soubory", "souborů")}, ${formatCount(findings, "nález", "nálezy", "nálezů")}`,
        ]
          .filter(Boolean)
          .join(": "),
      };
    }
    case "rule_pack_loaded":
    case "rule_pack_installed":
      return { title, detail: `${String(d.packId ?? "")} ${String(d.version ?? "")}` };
    case "quarantined":
    case "quarantine_restored":
    case "quarantine_deleted":
    case "quarantine_failed":
      return { title, detail: String(d.path ?? "") };
    case "remediated":
      return { title, detail: String(d.path ?? "") };
    case "rule_pack_rejected":
      return { title, detail: String(d.message ?? "") };
    case "engine_started":
      return { title, detail: `verze ${String(d.engineVersion ?? "")}` };
    case "audit_integrity_issue":
      return { title, detail: describeIntegrityIssue(String(d.detail ?? ""), d.sealed === true) };
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

/** „před 5 min“, „před 3 h“, jinak datum a čas. */
export function relativeTime(ms: number, now = Date.now()): string {
  const minutes = Math.round((now - ms) / 60_000);
  if (minutes < 1) return "právě teď";
  if (minutes < 60) return `před ${minutes} min`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `před ${hours} h`;
  return formatDateTime(ms);
}

export const WEEKDAYS = ["pondělí", "úterý", "středa", "čtvrtek", "pátek", "sobota", "neděle"];
