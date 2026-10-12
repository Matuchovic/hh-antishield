import { describe, expect, it } from "vitest";
import {
  agoText,
  categoriesWith,
  categoryList,
  commandStatus,
  commandTitle,
  compareVersions,
  connectionText,
  deviceHealth,
  deviceIssues,
  deviceTone,
  fleetHeadline,
  fleetTotals,
  groupFingerprint,
  initials,
  isExtended,
  isOnline,
  offersMore,
  policyRule,
  reclaimable,
  recommendations,
  securityChecks,
  shortName,
  supportsExtended,
} from "./fleet";
import type { FleetCommand, FleetDevice, FleetPolicy, FleetReport, FleetSecurity } from "./types";

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
    policy,
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
    deep: false,
    full: false,
    targets: [],
    count: 0,
    note: null,
    untilMs: null,
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
    expect(categoryList(["trash", "installers"])).toBe("staré instalátory a Koš");
  });

  it("shrne firmu do jedné věty", () => {
    const totals = fleetTotals(
      [
        device(),
        device({ id: "d2", lastSeenMs: NOW - 86_400_000, report: report({ protection: "manualScanOnly" }) }),
        device({ id: "d3", left: true }),
      ],
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

const DAY = 86_400_000;
const extended: FleetPolicy = {
  auto: ["appCaches", "logs", "developer"],
  consent: ["installers", "leftovers", "largeFiles", "trash"],
  actions: ["deepClean", "restart", "quitApps", "updates", "fullScan", "quarantineDelete"],
  share: ["hardware", "security", "performance", "threats"],
};

function security(over: Partial<FleetSecurity> = {}): FleetSecurity {
  return {
    filevault: true,
    firewall: true,
    stealth: false,
    sip: true,
    gatekeeper: true,
    xprotect: "5310",
    autoUpdates: true,
    osUpdates: [],
    backup: { configured: true, auto: true, lastMs: NOW - DAY },
    fullDiskAccess: true,
    ...over,
  };
}

describe("detail firemního Macu", () => {
  it("pojmenuje vypnuté ochrany systému lidsky a správně česky", () => {
    const checks = securityChecks(
      security({
        filevault: false,
        autoUpdates: null,
        osUpdates: [
          { title: "macOS Sequoia 15.7.1", version: "15.7.1", restart: true, recommended: true },
          { title: "Safari 26.0.1", version: null, restart: false, recommended: true },
        ],
        backup: { configured: true, auto: true, lastMs: NOW - 12 * DAY },
      }),
      NOW,
    );
    const find = (id: string) => checks.find((c) => c.id === id);
    expect(find("filevault")).toMatchObject({ state: "off", label: "Vypnuto", offTitle: "Disk není šifrovaný (FileVault)" });
    expect(find("updates")).toMatchObject({
      state: "off",
      label: "Čeká",
      offTitle: "Čekají 2 aktualizace macOS",
      detail: "Čekají 2 aktualizace: macOS Sequoia 15.7.1, Safari 26.0.1.",
    });
    expect(find("autoUpdates")).toMatchObject({ state: "unknown", label: "Nezjištěno" });
    expect(find("backup")).toMatchObject({ state: "off", label: "Stará", offTitle: "Poslední záloha proběhla před 12 dny" });
    expect(find("fullDiskAccess")).toMatchObject({ state: "on", label: "Povolen" });
    const none = securityChecks(security({ backup: { configured: false, auto: null, lastMs: null } }), NOW);
    expect(none.find((c) => c.id === "backup")).toMatchObject({ label: "Nenastavená", offTitle: "Mac se nezálohuje" });
    expect(none.find((c) => c.id === "updates")).toMatchObject({ state: "on", label: "Aktuální" });
  });

  it("nechválí Mac, o jehož zabezpečení nic neví", () => {
    const basic = deviceHealth(device(), "0.7.0", NOW);
    expect(basic).toMatchObject({ score: 100, partial: true, label: "Ze základních údajů", tone: "good" });

    const full = deviceHealth(device({ policy: extended, report: report({ security: security() }) }), "0.7.0", NOW);
    expect(full).toMatchObject({ score: 100, partial: false, label: "Výborný stav" });

    const weak = deviceHealth(
      device({
        policy: extended,
        report: report({
          security: security({ filevault: false, osUpdates: [{ title: "macOS 15.7.1", version: null, restart: true, recommended: true }] }),
        }),
      }),
      "0.7.0",
      NOW,
    );
    expect(weak.factors).toEqual([
      { text: "Disk není šifrovaný (FileVault)", points: 12 },
      { text: "Čeká aktualizace macOS", points: 5 },
    ]);
    expect(weak).toMatchObject({ score: 83, tone: "caution", label: "Chce pozornost" });
  });

  it("doporučí jen zásahy, které Mac dovolil", () => {
    const old = report({ appVersion: "0.7.0", uptimeSecs: 16 * 86_400, security: security({ firewall: false }) });
    const basicRecs = recommendations(device({ report: old }), "0.8.0", NOW);
    expect(basicRecs.find((r) => r.id === "update")?.action).toBeUndefined();
    expect(basicRecs.find((r) => r.id === "restart")?.action).toBeUndefined();

    const extRecs = recommendations(device({ policy: extended, report: old }), "0.8.0", NOW);
    expect(extRecs.find((r) => r.id === "update")?.action).toEqual({ label: "Aktualizovat", kind: "update" });
    expect(extRecs.find((r) => r.id === "restart")?.action).toEqual({ label: "Požádat o restart", kind: "restart" });
    expect(extRecs.find((r) => r.id === "security-firewall")).toMatchObject({ title: "Firewall je vypnutý", tab: "security" });
    expect(extRecs.map((r) => r.tone)).toEqual([...extRecs.map((r) => r.tone)].sort((a, b) => order(a) - order(b)));
  });

  it("rozšířenou správu nabídne jen Macu, který jí rozumí", () => {
    expect(supportsExtended(report({ appVersion: "0.7.0" }))).toBe(false);
    expect(supportsExtended(report({ appVersion: "0.8.0" }))).toBe(true);
    expect(supportsExtended(report({ appVersion: "0.10.1" }))).toBe(true);
    expect(supportsExtended(null)).toBe(false);
    const old = report({ appVersion: "0.7.0" });
    expect(recommendations(device({ report: old }), "0.8.0", NOW).find((r) => r.id === "update")?.detail).toBe(
      "Nejnovější verze je 0.8.0. Uživatel ji nainstaluje tlačítkem Aktualizovat v AntiShieldu.",
    );
    const basic08 = report({ appVersion: "0.8.0" });
    expect(recommendations(device({ report: basic08 }), "0.8.1", NOW).find((r) => r.id === "update")?.detail).toBe(
      "Nejnovější verze je 0.8.1. Na dálku ji jde spustit s rozšířenou správou.",
    );
  });

  it("pozná, kdy firma nabízí víc, než Mac potvrdil", () => {
    expect(isExtended(policy)).toBe(false);
    expect(isExtended(extended)).toBe(true);
    expect(offersMore(extended, policy)).toBe(true);
    expect(offersMore(extended, extended)).toBe(false);
    // Kategorie, kterou Mac smí uklidit hned, nabídka „se souhlasem“ nerozšiřuje.
    expect(offersMore({ auto: [], consent: ["appCaches"] }, policy)).toBe(false);
  });

  it("popíše nové zásahy a jejich výsledek", () => {
    expect(commandTitle(command({ deep: true }), extended)).toBe("Hloubková údržba");
    expect(commandTitle(command({ kind: "scan", full: true }), extended)).toBe("Úplná kontrola na dálku");
    expect(commandStatus(command({ kind: "restart", state: "awaitingConsent", untilMs: NOW + 3_600_000 })).text).toMatch(
      /^Uživatel odložil do \d{1,2}:\d{2}$/,
    );
    expect(commandStatus(command({ kind: "restart", state: "declined" })).text).toBe("Uživatel restart odmítl");
    expect(commandStatus(command({ kind: "quitApps", count: 2, targets: ["a", "b", "c"] })).text).toBe("Ukončeno 2 z 3");
    expect(commandStatus(command({ kind: "quitApps", count: 0, targets: ["a"] })).text).toBe("Aplikace neběžely");
    expect(commandStatus(command({ kind: "update", note: "0.8.0" })).text).toBe("Instaluje se 0.8.0");
    expect(commandStatus(command({ kind: "update" })).text).toBe("Aktuální");
    expect(commandStatus(command({ kind: "deleteQuarantine", count: 1, targets: ["q1", "q2"] })).text).toBe("Smazáno 1 z 2");
    expect(commandStatus(command({ kind: "policy", state: "declined" })).text).toBe("Uživatel rozšířenou správu odmítl");
  });
});

function order(tone: string): number {
  return tone === "alert" ? 0 : tone === "caution" ? 1 : 2;
}
