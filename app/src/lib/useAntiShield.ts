// Stav rozhraní: data z enginu, nastavení, ochrana na pozadí a průběh kontroly.
// Rozhraní nic nepředpokládá, vše zobrazuje podle toho, co hlásí backend.
import { useCallback, useEffect, useRef, useState } from "react";
import { api, asError, onAppEvent, onScanEvent } from "./api";
import { playCleaned, playScanDone, playScanStart, playThreat, setSoundEnabled } from "./sound";
import type {
  AuditEvent,
  Detection,
  EngineInfo,
  ErrorDto,
  Finding,
  PostureCheck,
  PresetScan,
  ProtectionSummary,
  QuarantineItem,
  RemediationReport,
  RuntimeInfo,
  ScanProgress,
  ScanSummary,
  Selection,
  SelfTestReport,
  Settings,
} from "./types";

export interface ScanState {
  scanId: string | null;
  running: boolean;
  roots: string[];
  progress: ScanProgress | null;
  liveFindings: Finding[];
}

const IDLE: ScanState = { scanId: null, running: false, roots: [], progress: null, liveFindings: [] };
const STATUS_REFRESH_MS = 10_000;

export function useAntiShield() {
  const [protection, setProtection] = useState<ProtectionSummary | null>(null);
  const [info, setInfo] = useState<EngineInfo | null>(null);
  const [engineError, setEngineError] = useState<ErrorDto | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [selection, setSelection] = useState<Selection | null>(null);
  const [scan, setScan] = useState<ScanState>(IDLE);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [selfTest, setSelfTest] = useState<SelfTestReport | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [runtime, setRuntime] = useState<RuntimeInfo | null>(null);
  const [quarantine, setQuarantine] = useState<QuarantineItem[]>([]);
  const [posture, setPosture] = useState<PostureCheck[] | null>(null);
  const [cleaning, setCleaning] = useState<Record<string, "busy" | RemediationReport>>({});
  const [rulesBusy, setRulesBusy] = useState(false);
  const [error, setError] = useState<ErrorDto | null>(null);
  const scanIdRef = useRef<string | null>(null);

  const refreshStatus = useCallback(async () => {
    try {
      setProtection(await api.protectionStatus());
      setRuntime(await api.runtimeInfo());
    } catch (e) {
      setError(asError(e));
    }
  }, []);

  const refreshQuarantine = useCallback(async () => {
    try {
      setQuarantine(await api.quarantineList());
    } catch {
      // Engine se ještě spouští; seznam se načte po události engine-ready.
    }
  }, []);

  const refresh = useCallback(async () => {
    await refreshStatus();
    try {
      setInfo(await api.engineInfo());
      setEngineError(null);
      setEvents(await api.recentEvents(30));
      setSummary(await api.lastSummary());
    } catch (e) {
      setEngineError(asError(e));
    }
    await refreshQuarantine();
  }, [refreshStatus, refreshQuarantine]);

  useEffect(() => {
    void api.getSettings().then((loaded) => {
      setSettings(loaded);
      setSoundEnabled(loaded.sounds);
    });
    void refresh();
    const timer = window.setInterval(() => void refreshStatus(), STATUS_REFRESH_MS);

    const stopScan = onScanEvent((event) => {
      // Kontrolu mohl spustit i plán nebo lišta: „started“ přijmeme vždy.
      if (event.type === "started") {
        scanIdRef.current = event.scanId;
        setScan({ ...IDLE, scanId: event.scanId, running: true, roots: event.roots });
        return;
      }
      if (scanIdRef.current && event.scanId !== scanIdRef.current) return;
      switch (event.type) {
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
          setCleaning({});
          playScanDone(event.summary.findings.length === 0);
          void refresh();
          break;
      }
    });
    const stops = [
      onAppEvent<boolean>("engine-ready", () => void refresh()),
      onAppEvent<unknown>("rules-updated", () => void refresh()),
      onAppEvent<unknown>("quarantine-changed", () => void refreshQuarantine()),
      onAppEvent<Detection>("protection-event", (detection) => {
        if (detection.action.type === "quarantined") playCleaned();
        else playThreat();
        void refreshStatus();
        void refreshQuarantine();
      }),
    ];
    return () => {
      window.clearInterval(timer);
      void stopScan.then((stop) => stop());
      for (const stop of stops) void stop.then((fn) => fn());
    };
  }, [refresh, refreshStatus, refreshQuarantine]);

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
      playScanStart();
      const id = await api.startScan(selection.id);
      scanIdRef.current = id;
      setScan((s) => ({ ...s, scanId: id }));
    } catch (e) {
      setScan(IDLE);
      setError(asError(e));
    }
  }, [selection]);

  const startPreset = useCallback(async (kind: PresetScan) => {
    setError(null);
    try {
      setScan({ ...IDLE, running: true, roots: [] });
      playScanStart();
      const id = await api.startPresetScan(kind);
      scanIdRef.current = id;
      setScan((s) => ({ ...s, scanId: id }));
    } catch (e) {
      setScan(IDLE);
      setError(asError(e));
    }
  }, []);

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

  const remediate = useCallback(
    async (paths: string[]) => {
      if (!paths.length) return;
      setError(null);
      setCleaning((c) => ({ ...c, ...Object.fromEntries(paths.map((p) => [p, "busy" as const])) }));
      try {
        const reports = await api.remediate(paths);
        setCleaning((c) => ({ ...c, ...Object.fromEntries(reports.map((r) => [r.path, r])) }));
        if (reports.some((r) => r.quarantined)) playCleaned();
        await refresh();
      } catch (e) {
        setCleaning((c) => {
          const next = { ...c };
          for (const p of paths) delete next[p];
          return next;
        });
        setError(asError(e));
      }
    },
    [refresh],
  );

  const restore = useCallback(
    async (id: string) => {
      try {
        await api.quarantineRestore(id);
        await refreshQuarantine();
      } catch (e) {
        setError(asError(e));
      }
    },
    [refreshQuarantine],
  );

  const deleteQuarantined = useCallback(
    async (id: string) => {
      try {
        await api.quarantineDelete(id);
        await refreshQuarantine();
      } catch (e) {
        setError(asError(e));
      }
    },
    [refreshQuarantine],
  );

  const refreshPosture = useCallback(async () => {
    setPosture(null);
    try {
      setPosture(await api.postureChecks());
    } catch (e) {
      setError(asError(e));
    }
  }, []);

  const saveSettings = useCallback(
    async (patch: Partial<Settings>) => {
      if (!settings) return;
      const next = { ...settings, ...patch };
      setSettings(next);
      setSoundEnabled(next.sounds);
      try {
        setSettings(await api.saveSettings(next));
        await refreshStatus();
      } catch (e) {
        setSettings(settings);
        setSoundEnabled(settings.sounds);
        setError(asError(e));
      }
    },
    [settings, refreshStatus],
  );

  const addWatchFolder = useCallback(async () => {
    if (!settings) return;
    try {
      const folder = await api.pickWatchFolder();
      if (folder && !settings.watchFolders.includes(folder)) {
        await saveSettings({ watchFolders: [...settings.watchFolders, folder] });
      }
    } catch (e) {
      setError(asError(e));
    }
  }, [settings, saveSettings]);

  const updateRules = useCallback(async () => {
    setRulesBusy(true);
    setError(null);
    try {
      await api.updateRulesNow();
      await refresh();
    } catch (e) {
      setError(asError(e));
      await refreshStatus();
    } finally {
      setRulesBusy(false);
    }
  }, [refresh, refreshStatus]);

  return {
    protection,
    info,
    engineError,
    events,
    selection,
    scan,
    summary,
    selfTest,
    settings,
    runtime,
    quarantine,
    posture,
    cleaning,
    rulesBusy,
    error,
    refresh,
    pick,
    start,
    startPreset,
    cancel,
    runSelfTest,
    remediate,
    restore,
    deleteQuarantined,
    refreshPosture,
    saveSettings,
    addWatchFolder,
    updateRules,
    clearSelection: () => setSelection(null),
    dismissError: () => setError(null),
  };
}

export type AntiShield = ReturnType<typeof useAntiShield>;
