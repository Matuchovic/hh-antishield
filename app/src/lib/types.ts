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
