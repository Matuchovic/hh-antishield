// Typy odpovídají serializaci z `antishield-core` (serde, camelCase).

export type Severity = "test_only" | "low" | "medium" | "high" | "critical";

export type Evidence =
  | { type: "sha256Match"; digestHex: string }
  | { type: "bytePattern"; offset: number; length: number }
  | { type: "eicarStandard" }
  | { type: "yaraMatch"; source: string; rule: string; author: string | null; reference: string | null };

export interface FileIdentity {
  device: number;
  inode: number;
  size: number;
  modifiedSec: number;
  modifiedNsec: number;
  changedSec: number;
  changedNsec: number;
}

export interface Finding {
  path: string;
  sha256: string;
  ruleId: string;
  ruleName: string;
  ruleVersion: number;
  ruleDescription: string;
  severity: Severity;
  testOnly: boolean;
  evidence: Evidence[];
  identity: FileIdentity;
  changedDuringRead: boolean;
  archiveEntry: string | null;
  origin: FindingOrigin | null;
}

export type FindingOrigin =
  | { type: "process"; pid: number; name: string }
  | { type: "startupItem"; location: string; label: string };

export type SkipReason =
  | { type: "symlink" }
  | { type: "notRegularFile" }
  | { type: "tooLarge"; size: number; limit: number }
  | { type: "notDownloaded" }
  | { type: "otherVolume" }
  | { type: "permissionDenied" }
  | { type: "notFound" }
  | { type: "timeout"; limitMs: number }
  | { type: "readError"; code: number | null; message: string }
  | { type: "internalError"; message: string };

export interface SkippedItem {
  path: string;
  reason: SkipReason;
}

export interface SkipCount {
  reason: SkipReason["type"];
  count: number;
}

export interface ScanProgress {
  filesScanned: number;
  bytesScanned: number;
  itemsSkipped: number;
  findings: number;
  currentPath: string | null;
  elapsedMs: number;
}

export type ScanOutcome =
  | { type: "completed" }
  | { type: "cancelled" }
  | { type: "failed"; reason: string };

export interface RulePackInfo {
  packId: string;
  version: string;
  sequence: number;
  ruleCount: number;
  signingKeyId: string;
  testPack: boolean;
  createdAtUnix: number;
  expiresAtUnix: number;
  expired: boolean;
  yaraRuleCount: number;
  sources: RuleSourceInfo[];
}

export interface RuleSourceInfo {
  id: string;
  name: string;
  url: string;
  license: string;
  ruleCount: number;
}

export interface ScanSummary {
  scanId: string;
  outcome: ScanOutcome;
  roots: string[];
  startedAtMs: number;
  finishedAtMs: number;
  filesScanned: number;
  bytesScanned: number;
  archivesNotInspected: number;
  yaraIncomplete: number;
  findings: Finding[];
  skippedTotal: number;
  skippedByReason: SkipCount[];
  skippedSample: SkippedItem[];
  rulePack: RulePackInfo;
  engineVersion: string;
}

export type ScanEvent =
  | { type: "started"; scanId: string; roots: string[] }
  | { type: "progress"; scanId: string; progress: ScanProgress }
  | { type: "findingDetected"; scanId: string; finding: Finding }
  | { type: "finished"; scanId: string; summary: ScanSummary };

export interface EngineInfo {
  engineVersion: string;
  platform: string;
  rulePack: RulePackInfo;
}

export interface SelfTestCheck {
  name: string;
  passed: boolean;
  detail: string;
}

export interface SelfTestReport {
  passed: boolean;
  ranAtMs: number;
  checks: SelfTestCheck[];
}

export interface AuditEvent {
  seq: number;
  tsMs: number;
  kind: string;
  data: Record<string, unknown>;
}

export type ComponentKind =
  | "detectionEngine"
  | "rulePack"
  | "auditLog"
  | "onDemandScan"
  | "realTimeProtection"
  | "webProtection"
  | "emailProtection"
  | "privacyProtection"
  | "quarantine"
  | "updates"
  | "systemCare";

export type ComponentState =
  | { type: "notImplemented" }
  | { type: "disabled" }
  | { type: "running"; verifiedAtMs: number }
  | { type: "degraded"; reason: string }
  | { type: "failed"; reason: string };

export interface ComponentStatus {
  kind: ComponentKind;
  state: ComponentState;
}

export type ProtectionLevel = "notReady" | "manualScanOnly" | "monitored" | "protected";

export interface ProtectionSummary {
  level: ProtectionLevel;
  components: ComponentStatus[];
}

export interface Selection {
  id: string;
  paths: string[];
}

export interface ErrorDto {
  code: string;
  message: string;
}

export interface UpdateInfo {
  version: string;
  currentVersion: string;
  notes: string | null;
}

export interface UpdateProgress {
  downloaded: number;
  total: number | null;
}

export interface QuarantineItem {
  id: string;
  originalPath: string;
  sha256: string;
  size: number;
  quarantinedAtMs: number;
  ruleId: string;
  ruleName: string;
  severity: Severity;
  testOnly: boolean;
}

export interface RemediationReport {
  path: string;
  quarantined: QuarantineItem | null;
  processTerminated: boolean;
  startupDisabled: boolean;
  problems: string[];
}

export type PostureState = "ok" | "warning" | "unknown";

export interface PostureCheck {
  id: string;
  title: string;
  state: PostureState;
  detail: string;
  advice: string;
}

export type Schedule = "off" | "daily" | "weekly";
export type PresetScan = "quick" | "full";

export interface Settings {
  protectionEnabled: boolean;
  watchFolders: string[];
  autoQuarantine: boolean;
  notifications: boolean;
  rulesAutoUpdate: boolean;
  schedule: Schedule;
  scheduleHour: number;
  scheduleWeekday: number;
  scheduleScan: PresetScan;
  sounds: boolean;
  intro: boolean;
  reducedMotion: boolean;
  launchAtLogin: boolean;
  keepRunningInBackground: boolean;
}

export type DetectionAction =
  | { type: "quarantined"; itemId: string }
  | { type: "detected" }
  | { type: "failed"; reason: string };

export interface Detection {
  atMs: number;
  finding: Finding;
  action: DetectionAction;
}

export interface RulesStatus {
  lastCheckMs: number | null;
  lastSuccessMs: number | null;
  lastError: string | null;
  checking: boolean;
}

export interface RuntimeInfo {
  watched: string[];
  watchingSinceMs: number | null;
  watchError: string | null;
  accessDenied: string | null;
  detections: Detection[];
  rules: RulesStatus;
  lastScheduledRunMs: number | null;
  backgroundProblem: string | null;
  lastCatchUp: CatchUp | null;
  startupWatched: boolean;
  programsChecked: number;
  programsSinceMs: number | null;
  /** Plný přístup k disku (macOS); jinde null. */
  fullDiskAccess: boolean | null;
  /** Co ochrana zkontrolovala od spuštění (radar). */
  activity: ActivityLog;
}

export type ActivityKind = "download" | "file" | "mail" | "program" | "startup";

/** Dávka skutečně zkontrolovaných položek (událost „activity“). */
export interface Activity {
  atMs: number;
  kind: ActivityKind;
  count: number;
  samples: { name: string; threat: boolean }[];
}

export interface RecentCheck {
  atMs: number;
  kind: ActivityKind | "scan";
  name: string;
  threat: boolean;
}

export interface ActivityLog {
  sinceMs: number | null;
  downloads: number;
  files: number;
  mail: number;
  programs: number;
  startup: number;
  threats: number;
  recent: RecentCheck[];
}

export type Channel = "web" | "email" | "airDrop" | "messages" | "externalDrive" | "unknown";

export interface Provenance {
  channel: Channel;
  downloadUrl: string | null;
  referrerUrl: string | null;
  emailFrom: string | null;
  savedBy: string | null;
  arrivedAtMs: number | null;
  createdAtMs: number | null;
  modifiedAtMs: number | null;
}

export interface ProcessLink {
  pid: number;
  name: string;
  path: string | null;
  startedAtMs: number | null;
}

export type StorySource = "realtime" | "program" | "startup" | "scan";

export type StoryOutcome =
  | { type: "quarantined"; itemId: string; processTerminated: boolean }
  | { type: "reported" }
  | { type: "failed"; reason: string };

/** Příběh útoku: od příchodu hrozby po zásah. */
export interface Story {
  id: string;
  detectedAtMs: number;
  source: StorySource;
  finding: Finding;
  provenance: Provenance;
  chain: ProcessLink[];
  outcome: StoryOutcome;
  updatedAtMs: number;
}

export interface PrivacyGrant {
  service: "camera" | "microphone" | "screen" | "accessibility" | "input" | "fullDisk";
  client: string;
}

export interface PrivacyReport {
  fullDiskAccess: boolean | null;
  grants: PrivacyGrant[];
  problem: string | null;
}

export interface CatchUp {
  atMs: number;
  sinceMs: number;
  checked: number;
  complete: boolean;
}

export type RuleUpdateOutcome =
  | { type: "installed"; rulePack: RulePackInfo }
  | { type: "upToDate"; rulePack: RulePackInfo };

// ---------- Čištění a zrychlení ----------

export type CleanCategory =
  | "appCaches"
  | "logs"
  | "developer"
  | "installers"
  | "leftovers"
  | "largeFiles"
  | "trash";

/** Jak se položka uklidí: smazat (vytvoří se znovu), do Koše (jde vrátit), vysypat Koš (nevratné). */
export type CleanMethod = "delete" | "moveToTrash" | "emptyTrash";

export interface CleanItem {
  id: string;
  category: CleanCategory;
  path: string;
  name: string;
  bytes: number;
  files: number;
  modifiedMs: number | null;
  recommended: boolean;
  method: CleanMethod;
  note: string | null;
}

export interface CleanScan {
  items: CleanItem[];
  startedAtMs: number;
  finishedAtMs: number;
  complete: boolean;
  unreadable: string[];
}

export interface CleanOutcome {
  freedBytes: number;
  trashedBytes: number;
  cleaned: string[];
  failed: { id: string; reason: string }[];
}

export type MemoryPressure = "normal" | "warning" | "critical";

export interface HeavyProcess {
  pid: number;
  name: string;
  path: string | null;
  cpu: number;
  memory: number;
  processes: number;
  bundleId: string | null;
  appPath: string | null;
}

export interface StartupEntry {
  id: string;
  label: string;
  plist: string;
  program: string | null;
  system: boolean;
  enabled: boolean;
  pid: number | null;
  cpu: number;
  memory: number;
}

export interface SpeedReport {
  disk: { total: number; free: number } | null;
  memory: { total: number; used: number; swapUsed: number; pressure: MemoryPressure | null };
  cpu: number;
  cores: number;
  uptimeSecs: number;
  heavy: HeavyProcess[];
  startup: StartupEntry[];
  measuredAtMs: number;
}

export type QuitOutcome = "quit" | "pending";

// ---------- Firemní správa ----------
// Správce (CTO) vidí firemní Macy a posílá jim podepsané příkazy; Mac je
// provede jen v mezích, se kterými jeho uživatel souhlasil při připojení.

export type FleetCommandKind = "cleanup" | "scan" | "isolate";

export type FleetCommandState =
  /** Čeká ve schránce, Mac je offline. */
  | "queued"
  /** Mac příkaz převzal a ověřil podpis. */
  | "delivered"
  | "running"
  /** Část úklidu čeká na souhlas uživatele Macu. */
  | "awaitingConsent"
  | "done"
  | "declined"
  | "failed"
  | "expired";

export interface FleetCommand {
  id: string;
  kind: FleetCommandKind;
  categories: CleanCategory[];
  sentAtMs: number;
  updatedAtMs: number;
  state: FleetCommandState;
  /** Úklid: uvolněno hned a přesunuto do Koše. */
  freedBytes: number;
  trashedBytes: number;
  /** Kontrola: zkontrolované soubory a nálezy; izolace: izolované hrozby. */
  files: number;
  threats: number;
  error: string | null;
}

export interface FleetThreat {
  ruleName: string;
  severity: Severity;
  path: string;
  detectedAtMs: number;
  quarantined: boolean;
}

/** Šifrovaná zpráva z Macu, ověřená podpisem jeho klíče. */
export interface FleetReport {
  /** Pořadí zpráv Macu (starší zpráva nepřepíše novější). */
  seq: number;
  createdAtMs: number;
  appVersion: string;
  osVersion: string;
  model: string;
  protection: ProtectionLevel;
  protectionNote: string | null;
  rulesVersion: string;
  rulesCheckedAtMs: number | null;
  lastScan: { atMs: number; files: number; threats: number } | null;
  threats: FleetThreat[];
  quarantined: number;
  disk: { total: number; free: number } | null;
  memory: { total: number; used: number; pressure: MemoryPressure | null };
  uptimeSecs: number;
  /** Kolik jde uklidit, jen velikosti po kategoriích (žádné názvy souborů). */
  cleanup: { measuredAtMs: number; categories: { category: CleanCategory; bytes: number }[] } | null;
}

export interface FleetDevice {
  id: string;
  /** Jméno, které správce zadal při pozvání. */
  name: string;
  fingerprint: string;
  joinedAtMs: number;
  /** Poslední spojení se schránkou (Mac se hlásí zhruba každou minutu). */
  lastSeenMs: number | null;
  /** Uživatel Mac od firmy odpojil. */
  left: boolean;
  report: FleetReport | null;
  /** Poslední příkazy, nejnovější první. */
  commands: FleetCommand[];
}

export interface FleetInvite {
  id: string;
  name: string;
  code: string;
  createdAtMs: number;
  expiresAtMs: number;
}

export interface FleetPolicy {
  /** Smí se na dálku hned (uživatel dostane oznámení). */
  auto: CleanCategory[];
  /** Jen po souhlasu uživatele Macu. Ostatní kategorie nikdy na dálku. */
  consent: CleanCategory[];
}

export interface FleetAdmin {
  fleetName: string;
  adminName: string;
  fingerprint: string;
  policy: FleetPolicy;
  devices: FleetDevice[];
  invites: FleetInvite[];
  relay: { reachable: boolean; checkedAtMs: number | null; error: string | null };
}

export interface FleetApproval {
  id: string;
  categories: CleanCategory[];
  bytes: number;
  requestedAtMs: number;
  expiresAtMs: number;
}

export interface FleetMembership {
  fleetName: string;
  adminName: string;
  adminFingerprint: string;
  joinedAtMs: number;
  lastContactMs: number | null;
  policy: FleetPolicy;
  approvals: FleetApproval[];
  /** Potíž se schránkou (kód chyby), jinak null. */
  problem: string | null;
}

export interface FleetJoinPreview {
  fleetName: string;
  adminName: string;
  adminFingerprint: string;
  deviceName: string;
  policy: FleetPolicy;
}

export interface FleetState {
  admin: FleetAdmin | null;
  member: FleetMembership | null;
}
