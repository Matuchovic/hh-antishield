// Stav rozhraní: data z enginu a průběh kontroly. Rozhraní nic nepředpokládá,
// vše zobrazuje podle toho, co engine hlásí.
import { useCallback, useEffect, useRef, useState } from "react";
import { api, asError, onScanEvent } from "./api";
import type {
  AuditEvent,
  EngineInfo,
  ErrorDto,
  Finding,
  ProtectionSummary,
  ScanProgress,
  ScanSummary,
  Selection,
  SelfTestReport,
} from "./types";

export interface ScanState {
  scanId: string | null;
  running: boolean;
  roots: string[];
  progress: ScanProgress | null;
  liveFindings: Finding[];
}

const IDLE: ScanState = { scanId: null, running: false, roots: [], progress: null, liveFindings: [] };

export function useAntiShield() {
  const [protection, setProtection] = useState<ProtectionSummary | null>(null);
  const [info, setInfo] = useState<EngineInfo | null>(null);
  const [engineError, setEngineError] = useState<ErrorDto | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [selection, setSelection] = useState<Selection | null>(null);
  const [scan, setScan] = useState<ScanState>(IDLE);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [selfTest, setSelfTest] = useState<SelfTestReport | null>(null);
  const [error, setError] = useState<ErrorDto | null>(null);
  const scanIdRef = useRef<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setProtection(await api.protectionStatus());
    } catch (e) {
      setError(asError(e));
    }
    try {
      setInfo(await api.engineInfo());
      setEngineError(null);
      setEvents(await api.recentEvents(30));
      setSummary(await api.lastSummary());
    } catch (e) {
      setEngineError(asError(e));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const unlisten = onScanEvent((event) => {
      if (scanIdRef.current && event.scanId !== scanIdRef.current) return;
      switch (event.type) {
        case "started":
          setScan((s) => ({ ...s, running: true, roots: event.roots }));
          break;
        case "progress":
          setScan((s) => ({ ...s, progress: event.progress }));
          break;
        case "findingDetected":
          setScan((s) => ({ ...s, liveFindings: [...s.liveFindings, event.finding] }));
          break;
        case "finished":
          scanIdRef.current = null;
          setScan((s) => ({ ...s, running: false }));
          setSummary(event.summary);
          void refresh();
          break;
      }
    });
    return () => {
      void unlisten.then((stop) => stop());
    };
  }, [refresh]);

  const pick = useCallback(async (kind: "folders" | "files") => {
    setError(null);
    try {
      const picked = await api.pickTargets(kind);
      if (picked) setSelection(picked);
    } catch (e) {
      setError(asError(e));
    }
  }, []);

  const start = useCallback(async () => {
    if (!selection) return;
    setError(null);
    try {
      setScan({ ...IDLE, running: true, roots: selection.paths });
      const id = await api.startScan(selection.id);
      scanIdRef.current = id;
      setScan((s) => ({ ...s, scanId: id }));
    } catch (e) {
      setScan(IDLE);
      setError(asError(e));
    }
  }, [selection]);

  const cancel = useCallback(async () => {
    try {
      await api.cancelScan();
    } catch (e) {
      setError(asError(e));
    }
  }, []);

  const runSelfTest = useCallback(async () => {
    try {
      setSelfTest(await api.runSelfTest());
      await refresh();
    } catch (e) {
      setError(asError(e));
    }
  }, [refresh]);

  return {
    protection,
    info,
    engineError,
    events,
    selection,
    scan,
    summary,
    selfTest,
    error,
    refresh,
    pick,
    start,
    cancel,
    runSelfTest,
    clearSelection: () => setSelection(null),
    dismissError: () => setError(null),
  };
}

export type AntiShield = ReturnType<typeof useAntiShield>;
