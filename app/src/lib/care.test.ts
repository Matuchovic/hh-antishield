import { describe, expect, it } from "vitest";
import {
  defaultSelection,
  diskTone,
  failureText,
  groupByCategory,
  memoryTone,
  noteText,
  selectedBytes,
  speedAdvice,
  startupName,
  trashItem,
  uptimeText,
} from "./care";
import type { CleanItem, CleanScan, SpeedReport } from "./types";

const GB = 1_000_000_000;

function item(over: Partial<CleanItem>): CleanItem {
  return {
    id: "x",
    category: "appCaches",
    path: "/Users/a/Library/Caches/com.vendor.app",
    name: "com.vendor.app",
    bytes: 1000,
    files: 3,
    modifiedMs: null,
    recommended: true,
    method: "delete",
    note: null,
    ...over,
  };
}

const scan: CleanScan = {
  items: [
    item({ id: "cache", bytes: 3 * GB }),
    item({ id: "busy", bytes: GB, recommended: false, note: "in use" }),
    item({ id: "dmg", category: "installers", method: "moveToTrash", bytes: 2 * GB }),
    item({ id: "trash", category: "trash", method: "emptyTrash", bytes: 5 * GB, recommended: false }),
  ],
  startedAtMs: 0,
  finishedAtMs: 1,
  complete: true,
  unreadable: [],
};

function report(over: Partial<SpeedReport>): SpeedReport {
  return {
    disk: { total: 500 * GB, free: 200 * GB },
    memory: { total: 16 * GB, used: 8 * GB, swapUsed: 0, pressure: "normal" },
    cpu: 12,
    cores: 8,
    uptimeSecs: 3600,
    heavy: [],
    startup: [],
    measuredAtMs: 0,
    ...over,
  };
}

describe("čištění", () => {
  it("předvybere jen doporučené položky a nikdy Koš", () => {
    expect([...defaultSelection(scan)].sort()).toEqual(["cache", "dmg"]);
  });

  it("odliší, co se uvolní hned a co jde do Koše", () => {
    const total = selectedBytes(scan, new Set(["cache", "dmg", "trash"]));
    expect(total).toEqual({ freed: 3 * GB, trashed: 2 * GB, total: 5 * GB, count: 2 });
  });

  it("seskupí položky v pevném pořadí kategorií", () => {
    expect(groupByCategory(scan).map((g) => g.category)).toEqual(["appCaches", "installers", "trash"]);
    expect(groupByCategory(scan)[0]?.bytes).toBe(4 * GB);
    expect(trashItem(scan)?.id).toBe("trash");
  });

  it("přeloží poznámky a důvody selhání do češtiny", () => {
    expect(noteText("in use")).toContain("používá");
    expect(noteText("unknown note")).toBeNull();
    expect(failureText("symbolic link")).toContain("změnila");
    expect(failureText("Permission denied (os error 13)")).toContain("Nepodařilo");
  });
});

describe("zrychlení", () => {
  it("varuje před plným diskem podle podílu i absolutně", () => {
    expect(diskTone({ total: 500 * GB, free: 200 * GB })).toBe("good");
    expect(diskTone({ total: 500 * GB, free: 80 * GB })).toBe("caution");
    expect(diskTone({ total: 500 * GB, free: 8 * GB })).toBe("alert");
    expect(diskTone({ total: 64 * GB, free: 9 * GB })).toBe("alert");
  });

  it("u paměti věří tlaku podle systému", () => {
    expect(memoryTone({ total: 16 * GB, used: 15.8 * GB, swapUsed: 0, pressure: "normal" })).toBe("good");
    expect(memoryTone({ total: 16 * GB, used: 8 * GB, swapUsed: 0, pressure: "critical" })).toBe("alert");
    expect(memoryTone({ total: 16 * GB, used: 15.8 * GB, swapUsed: 0, pressure: null })).toBe("caution");
  });

  it("radí jen podle naměřených hodnot", () => {
    expect(speedAdvice(report({}))).toEqual([]);
    const advice = speedAdvice(
      report({
        disk: { total: 250 * GB, free: 6 * GB },
        memory: { total: 8 * GB, used: 7.5 * GB, swapUsed: 3 * GB, pressure: "warning" },
        cpu: 91,
        uptimeSecs: 20 * 86_400,
      }),
    );
    expect(advice.map((a) => a.tone)).toEqual(["alert", "caution", "caution", "alert", "caution"]);
    expect(advice[4]?.text).toContain("20 dní");
  });

  it("čte dobu běhu a jména položek po přihlášení", () => {
    expect(uptimeText(90)).toBe("1 min");
    expect(uptimeText(3 * 3600 + 120)).toBe("3 h 2 min");
    expect(uptimeText(86_400 + 7200)).toBe("1 den 2 h");
    expect(uptimeText(3 * 86_400)).toBe("3 dny");
    const entry = {
      id: "a",
      label: "com.vendor.updater",
      plist: "/Users/a/Library/LaunchAgents/com.vendor.updater.plist",
      program: "/Applications/Vendor.app/Contents/MacOS/VendorUpdater",
      system: false,
      enabled: true,
      pid: null,
      cpu: 0,
      memory: 0,
    };
    expect(startupName(entry)).toBe("VendorUpdater");
    expect(startupName({ ...entry, program: null })).toBe("com.vendor.updater");
  });
});
