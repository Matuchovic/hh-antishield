import { describe, expect, it } from "vitest";
import {
  agoText,
  categoriesWith,
  categoryList,
  commandStatus,
  compareVersions,
  connectionText,
  deviceIssues,
  deviceTone,
  fleetHeadline,
  fleetTotals,
  groupFingerprint,
  initials,
  isOnline,
  policyRule,
  reclaimable,
  shortName,
} from "./fleet";
import type { FleetCommand, FleetDevice, FleetPolicy, FleetReport } from "./types";

const NOW = 1_800_000_000_000;
const GB = 1_000_000_000;
const policy: FleetPolicy = { auto: ["appCaches", "logs", "developer"], consent: ["installers", "leftovers"] };

function report(over: Partial<FleetReport> = {}): FleetReport {
  return {
    seq: 1,
    createdAtMs: NOW,
    appVersion: "0.7.0",
    osVersion: "macOS 26.0.1",
    model: "MacBook Pro (Apple M3 Pro)",
    protection: "monitored",
    protectionNote: null,
    rulesVersion: "2026.10.12",
    rulesCheckedAtMs: NOW - 3_600_000,
    lastScan: null,
    threats: [],
    quarantined: 0,
    disk: { total: 500 * GB, free: 200 * GB },
    memory: { total: 16 * GB, used: 8 * GB, pressure: "normal" },
    uptimeSecs: 3600,
    cleanup: {
      measuredAtMs: NOW,
      categories: [
        { category: "appCaches", bytes: 6 * GB },
        { category: "installers", bytes: 4 * GB },
        { category: "largeFiles", bytes: 20 * GB },
      ],
    },
    ...over,
  };
}

function device(over: Partial<FleetDevice> = {}): FleetDevice {
  return {
    id: "d1",
    name: "Petr Novák",
    fingerprint: "5d117f3a91c24b0e",
    joinedAtMs: NOW - 86_400_000,
    lastSeenMs: NOW - 20_000,
    left: false,
    report: report(),
    commands: [],
    ...over,
  };
}

function command(over: Partial<FleetCommand> = {}): FleetCommand {
  return {
    id: "c1",
    kind: "cleanup",
    categories: ["appCaches"],
    sentAtMs: NOW,
    updatedAtMs: NOW,
    state: "done",
    freedBytes: 0,
    trashedBytes: 0,
    files: 0,
    threats: 0,
    error: null,
    ...over,
  };
}

describe("firemní Macy", () => {
  it("pozná online Mac podle posledního hlášení", () => {
    expect(isOnline(device(), NOW)).toBe(true);
    expect(isOnline(device({ lastSeenMs: NOW - 4 * 60_000 }), NOW)).toBe(false);
    expect(isOnline(device({ left: true }), NOW)).toBe(false);
    expect(connectionText(device({ lastSeenMs: NOW - 3 * 3_600_000 }), NOW)).toBe("Offline, naposledy před 3 h");
    expect(connectionText(device({ lastSeenMs: null }), NOW)).toBe("Ještě se nepřipojil");
    expect(agoText(NOW - 2 * 86_400_000, NOW)).toBe("před 2 dny");
    expect(agoText(NOW - 86_400_000, NOW)).toBe("před 1 dnem");
  });

  it("řadí problémy od nejvážnějšího a hlídá zastaralou verzi", () => {
    const threat = { ruleName: "MAL_X", severity: "high" as const, path: "/a", detectedAtMs: NOW, quarantined: false };
    const issues = deviceIssues(
      device({ report: report({ appVersion: "0.6.0", threats: [threat], disk: { total: 256 * GB, free: 18 * GB } }) }),
      "0.7.0",
      NOW,
    );
    expect(issues.map((i) => i.tone)).toEqual(["alert", "alert", "caution"]);
    expect(issues[0]?.text).toBe("1 hrozba čeká na zásah");
    expect(deviceTone(device(), "0.7.0", NOW)).toBe("good");
    expect(deviceTone(device({ report: report({ protection: "manualScanOnly" }) }), "0.7.0", NOW)).toBe("caution");
    expect(deviceIssues(device({ report: null }), "0.7.0", NOW)[0]?.text).toBe("Mac zatím neposlal svůj stav");
    expect(compareVersions("0.6.0", "0.7.0")).toBeLessThan(0);
    expect(compareVersions("0.10.0", "0.9.9")).toBeGreaterThan(0);
  });

  it("počítá, co jde uklidit podle zásad (velké soubory nikdy)", () => {
    const r = report();
    expect(policyRule(policy, "appCaches")).toBe("auto");
    expect(policyRule(policy, "installers")).toBe("consent");
    expect(policyRule(policy, "largeFiles")).toBe("never");
    expect(reclaimable(r, policy, "auto")).toBe(6 * GB);
    expect(reclaimable(r, policy, "consent")).toBe(4 * GB);
    expect(reclaimable(r, policy, "never")).toBe(20 * GB);
    expect(categoriesWith(r, policy, "auto")).toEqual(["appCaches"]);
    expect(categoryList(policy.auto)).toBe("mezipaměti aplikací, staré protokoly a vývojářské mezipaměti");
  });

  it("shrne firmu do jedné věty", () => {
    const totals = fleetTotals(
      [
        device(),
        device({ id: "d2", lastSeenMs: NOW - 86_400_000, report: report({ protection: "manualScanOnly" }) }),
        device({ id: "d3", left: true }),
      ],
      policy,
      "0.7.0",
      NOW,
    );
    expect(totals.devices).toBe(2);
    expect(totals.online).toBe(1);
    expect(totals.autoBytes).toBe(12 * GB);
    expect(fleetHeadline(totals)).toBe("1 Mac potřebuje pozornost");
    expect(fleetHeadline({ ...totals, attention: 0 })).toBe("Všechny Macy jsou v pořádku");
    expect(fleetHeadline({ ...totals, attention: 5 })).toBe("5 Maců potřebuje pozornost");
  });

  it("popíše stav příkazu česky", () => {
    expect(commandStatus(command({ state: "queued" })).text).toBe("Čeká, až se Mac připojí");
    expect(commandStatus(command({ freedBytes: 3.2 * GB })).text).toBe("Uvolněno 3,2 GB");
    expect(commandStatus(command({ trashedBytes: 1.8 * GB })).text).toBe("1,8 GB v Koši");
    expect(commandStatus(command({ kind: "scan", files: 18234 })).text).toBe("18\u00a0234 souborů, bez nálezu");
    expect(commandStatus(command({ kind: "scan", threats: 2 })).tone).toBe("alert");
    expect(commandStatus(command({ state: "awaitingConsent" })).tone).toBe("busy");
  });

  it("zkrátí jména a otisky pro mapu", () => {
    expect(initials("Petr Novák")).toBe("PN");
    expect(shortName("Jana Dvořáková")).toBe("Jana D.");
    expect(shortName("Ondřej")).toBe("Ondřej");
    expect(groupFingerprint("7f3a91c24b0e5d11")).toBe("7F3A 91C2 4B0E 5D11");
  });
});
