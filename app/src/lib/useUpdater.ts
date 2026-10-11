// Aktualizace aplikace. Kontrola po startu a pak každých 6 hodin; instaluje se
// jen na pokyn uživatele. Podpis ověřuje backend, rozhraní jen ukazuje stav.
import { useCallback, useEffect, useState } from "react";
import { api, asError, onUpdateProgress } from "./api";
import type { ErrorDto, UpdateInfo, UpdateProgress } from "./types";

export type UpdateStatus = "idle" | "checking" | "upToDate" | "available" | "installing" | "error";

export interface Updater {
  status: UpdateStatus;
  info: UpdateInfo | null;
  progress: UpdateProgress | null;
  error: ErrorDto | null;
  dismissed: boolean;
  check: () => Promise<void>;
  install: () => Promise<void>;
  dismiss: () => void;
}

const FIRST_CHECK_MS = 4_000;
const CHECK_EVERY_MS = 6 * 60 * 60 * 1000;

export function useUpdater(): Updater {
  const [status, setStatus] = useState<UpdateStatus>("idle");
  const [info, setInfo] = useState<UpdateInfo | null>(null);
  const [progress, setProgress] = useState<UpdateProgress | null>(null);
  const [error, setError] = useState<ErrorDto | null>(null);
  const [dismissed, setDismissed] = useState(false);

  const check = useCallback(async () => {
    setStatus("checking");
    setError(null);
    try {
      const found = await api.checkUpdate();
      setInfo(found);
      setStatus(found ? "available" : "upToDate");
      if (found) setDismissed(false);
    } catch (e) {
      setError(asError(e));
      setStatus("error");
    }
  }, []);

  const install = useCallback(async () => {
    setStatus("installing");
    setProgress(null);
    setError(null);
    try {
      // Znovu načíst nabídku: backend si drží jen poslední zjištěnou verzi.
      const found = await api.checkUpdate();
      if (!found) {
        setInfo(null);
        setStatus("upToDate");
        return;
      }
      setInfo(found);
      // Po úspěšné instalaci se aplikace sama restartuje.
      await api.installUpdate();
    } catch (e) {
      setError(asError(e));
      setStatus("error");
    }
  }, []);

  useEffect(() => {
    const first = window.setTimeout(() => void check(), FIRST_CHECK_MS);
    const every = window.setInterval(() => void check(), CHECK_EVERY_MS);
    const unlisten = onUpdateProgress(setProgress);
    return () => {
      window.clearTimeout(first);
      window.clearInterval(every);
      void unlisten.then((fn) => fn());
    };
  }, [check]);

  return { status, info, progress, error, dismissed, check, install, dismiss: () => setDismissed(true) };
}
