// Jediné místo, kde rozhraní mluví s backendem. Volat lze jen příkazy
// povolené v src-tauri/capabilities/default.json.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  Activity,
  AuditEvent,
  CleanCategory,
  CleanOutcome,
  CleanScan,
  QuitOutcome,
  SpeedReport,
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
  FleetAdmin,
  FleetCommandKind,
  FleetInvite,
  FleetJoinPreview,
  FleetMembership,
  FleetState,
  ProtectionSummary,
  ScanEvent,
  ScanSummary,
  Selection,
  SelfTestReport,
  Story,
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
  restartApp: () => invoke<void>("restart_app"),
  threatStories: () => invoke<Story[]>("threat_stories"),
  getSettings: () => invoke<Settings>("get_settings"),
  saveSettings: (settings: Settings) => invoke<Settings>("save_settings", { settings }),
  pickWatchFolder: () => invoke<string | null>("pick_watch_folder"),
  checkUpdate: () => invoke<UpdateInfo | null>("check_update"),
  installUpdate: () => invoke<void>("install_update"),
  cleanScan: () => invoke<CleanScan>("clean_scan"),
  cleanCancel: () => invoke<void>("clean_cancel"),
  cleanLast: () => invoke<CleanScan | null>("clean_last"),
  cleanItems: (ids: string[]) => invoke<CleanOutcome>("clean_items", { ids }),
  cleanEmptyTrash: () => invoke<CleanOutcome>("clean_empty_trash"),
  speedReport: () => invoke<SpeedReport>("speed_report"),
  speedQuit: (pid: number) => invoke<QuitOutcome>("speed_quit", { pid }),
  speedStartup: (id: string, enabled: boolean) => invoke<SpeedReport>("speed_startup", { id, enabled }),
  // Firemní správa: správce (podepisuje příkazy) i spravovaný Mac.
  fleetState: () => invoke<FleetState>("fleet_state"),
  fleetCreate: (fleetName: string, adminName: string) => invoke<FleetAdmin>("fleet_create", { fleetName, adminName }),
  fleetRefresh: () => invoke<FleetAdmin>("fleet_refresh"),
  fleetInvite: (name: string) => invoke<FleetInvite>("fleet_invite", { name }),
  fleetCommand: (deviceIds: string[], kind: FleetCommandKind, categories: CleanCategory[]) =>
    invoke<FleetAdmin>("fleet_command", { deviceIds, kind, categories }),
  fleetRemoveDevice: (id: string) => invoke<FleetAdmin>("fleet_remove_device", { id }),
  fleetJoinPreview: (code: string) => invoke<FleetJoinPreview>("fleet_join_preview", { code }),
  fleetJoin: (code: string) => invoke<FleetMembership>("fleet_join", { code }),
  fleetLeave: () => invoke<void>("fleet_leave"),
  fleetApprove: (id: string, approve: boolean) => invoke<FleetMembership>("fleet_approve", { id, approve }),
};

/** Čištění: kategorie, kterou sken právě prochází. */
export function onCleanProgress(handler: (category: CleanCategory) => void): Promise<UnlistenFn> {
  return listen<CleanCategory>("clean-progress", (message) => handler(message.payload));
}

export function onScanEvent(handler: (event: ScanEvent) => void): Promise<UnlistenFn> {
  return listen<ScanEvent>("scan-event", (message) => handler(message.payload));
}

export function onUpdateProgress(handler: (progress: UpdateProgress) => void): Promise<UnlistenFn> {
  return listen<UpdateProgress>("update-progress", (message) => handler(message.payload));
}

/** Události backendu pro rozhraní. */
export function onAppEvent<T>(name: "engine-ready" | "protection-event" | "rules-updated" | "quarantine-changed" | "navigate" | "scheduled-scan" | "access-changed" | "stories-changed" | "fleet-changed", handler: (payload: T) => void): Promise<UnlistenFn> {
  return listen<T>(name, (message) => handler(message.payload));
}

/** Radar: dávky skutečně zkontrolovaných položek z hlídání. */
export function onActivity(handler: (activity: Activity) => void): Promise<UnlistenFn> {
  return listen<Activity>("activity", (message) => handler(message.payload));
}

export type { Detection };

export function asError(error: unknown): ErrorDto {
  if (error && typeof error === "object" && "code" in error && "message" in error) {
    return error as ErrorDto;
  }
  return { code: "unknown", message: String(error) };
}
