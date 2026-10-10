// Typy odpovídají serializaci z `antishield-core` (serde, camelCase).

export type Severity = "test_only" | "low" | "medium" | "high" | "critical";

export type Evidence =
  | { type: "sha256Match"; digestHex: string }
  | { type: "bytePattern"; offset: number; length: number }
  | { type: "eicarStandard" };

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
}

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

export type ProtectionLevel = "notReady" | "manualScanOnly" | "protected";

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
