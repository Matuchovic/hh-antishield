// Firemní správa: role tohoto Macu (správce, spravovaný Mac) a jejich data.
import { useCallback, useEffect, useState } from "react";
import { api, onAppEvent } from "./api";
import type { FleetAdmin, FleetMembership, FleetState } from "./types";

const REFRESH_MS = 20_000;

export interface Fleet extends FleetState {
  refresh: () => Promise<void>;
  setAdmin: (admin: FleetAdmin | null) => void;
  setMember: (member: FleetMembership | null) => void;
}

export function useFleet(): Fleet {
  const [state, setState] = useState<FleetState>({ admin: null, member: null });

  const refresh = useCallback(async () => {
    try {
      setState(await api.fleetState());
    } catch {
      // Firemní správa je volitelná; bez ní aplikace běží dál.
    }
  }, []);

  useEffect(() => {
    void refresh();
    const stop = onAppEvent("fleet-changed", () => void refresh());
    const timer = setInterval(() => void refresh(), REFRESH_MS);
    return () => {
      clearInterval(timer);
      void stop.then((fn) => fn());
    };
  }, [refresh]);

  const setAdmin = useCallback((admin: FleetAdmin | null) => setState((s) => ({ ...s, admin })), []);
  const setMember = useCallback((member: FleetMembership | null) => setState((s) => ({ ...s, member })), []);
  return { ...state, refresh, setAdmin, setMember };
}
