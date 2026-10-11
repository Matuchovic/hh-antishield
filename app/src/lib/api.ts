// Jediné místo, kde rozhraní mluví s backendem. Volat lze jen příkazy
// povolené v src-tauri/capabilities/default.json.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AuditEvent,
  Detection,
  PostureCheck,
  PrivacyReport,
  PresetScan,
  QuarantineItem,
  RemediationReport,
  RuleUpdateOutcome,
  RuntimeInfo,
  Settings,
  EngineInfo,
  ErrorDto,
  ProtectionSummary,
  ScanEvent,
  ScanSummary,
  Selection,
  SelfTestReport,
  UpdateInfo,
  UpdateProgress,
} from "./types";

export const api = {
  engineInfo: () => invoke<EngineInfo>("engine_info"),
  protectionStatus: () => invoke<ProtectionSummary>("protection_status"),
  runSelfTest: () => invoke<SelfTestReport>("run_self_test"),
  pickTargets: (kind: "folders" | "files") =>
    invoke<Selection | null>("pick_targets", { kind }),
  startScan: (selectionId: string) => invoke<string>("start_scan", { selectionId }),
  cancelScan: () => invoke<void>("cancel_scan"),
  recentEvents: (limit: number) => invoke<AuditEvent[]>("recent_events", { limit }),
  lastSummary: () => invoke<ScanSummary | null>("last_summary"),
  startPresetScan: (kind: PresetScan) => invoke<string>("start_preset_scan", { kind }),
  remediate: (paths: string[]) => invoke<RemediationReport[]>("remediate", { paths }),
  quarantineList: () => invoke<QuarantineItem[]>("quarantine_list"),
  quarantineRestore: (id: string) => invoke<QuarantineItem>("quarantine_restore", { id }),
  quarantineDelete: (id: string) => invoke<QuarantineItem>("quarantine_delete", { id }),
  postureChecks: () => invoke<PostureCheck[]>("posture_checks"),
  openSystemSettings: (checkId: string) => invoke<void>("open_system_settings", { checkId }),
  privacyReport: () => invoke<PrivacyReport>("privacy_report"),
  updateRulesNow: () => invoke<RuleUpdateOutcome>("update_rules_now"),
  runtimeInfo: () => invoke<RuntimeInfo>("runtime_info"),
  getSettings: () => invoke<Settings>("get_settings"),
  saveSettings: (settings: Settings) => invoke<Settings>("save_settings", { settings }),
  pickWatchFolder: () => invoke<string | null>("pick_watch_folder"),
  checkUpdate: () => invoke<UpdateInfo | null>("check_update"),
  installUpdate: () => invoke<void>("install_update"),
};

export function onScanEvent(handler: (event: ScanEvent) => void): Promise<UnlistenFn> {
  return listen<ScanEvent>("scan-event", (message) => handler(message.payload));
}

export function onUpdateProgress(handler: (progress: UpdateProgress) => void): Promise<UnlistenFn> {
  return listen<UpdateProgress>("update-progress", (message) => handler(message.payload));
}

/** Události backendu pro rozhraní. */
export function onAppEvent<T>(name: "engine-ready" | "protection-event" | "rules-updated" | "quarantine-changed" | "navigate" | "scheduled-scan", handler: (payload: T) => void): Promise<UnlistenFn> {
  return listen<T>(name, (message) => handler(message.payload));
}

export type { Detection };

export function asError(error: unknown): ErrorDto {
  if (error && typeof error === "object" && "code" in error && "message" in error) {
    return error as ErrorDto;
  }
  return { code: "unknown", message: String(error) };
}
