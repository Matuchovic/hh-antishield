// Jediné místo, kde rozhraní mluví s backendem. Volat lze jen příkazy
// povolené v src-tauri/capabilities/default.json.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AuditEvent,
  EngineInfo,
  ErrorDto,
  ProtectionSummary,
  ScanEvent,
  ScanSummary,
  Selection,
  SelfTestReport,
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
};

export function onScanEvent(handler: (event: ScanEvent) => void): Promise<UnlistenFn> {
  return listen<ScanEvent>("scan-event", (message) => handler(message.payload));
}

export function asError(error: unknown): ErrorDto {
  if (error && typeof error === "object" && "code" in error && "message" in error) {
    return error as ErrorDto;
  }
  return { code: "unknown", message: String(error) };
}
