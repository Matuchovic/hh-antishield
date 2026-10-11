import { describe, expect, it } from "vitest";
import { hostOf, shortDuration, storyAdvice, storyFor, storySteps, storySummary } from "./story";
import type { Story } from "./types";

const T0 = Date.UTC(2026, 9, 11, 12, 0, 0);

function story(overrides: Partial<Story> = {}): Story {
  return {
    id: "s1",
    detectedAtMs: T0 + 2000,
    source: "realtime",
    finding: {
      path: "/Users/eva/Downloads/invoice.zip",
      sha256: "ab".repeat(32),
      ruleId: "forge_core.MAL_Macos_Stealer_Atomic",
      ruleName: "MAL_Macos_Stealer_Atomic",
      ruleVersion: 1,
      ruleDescription: "",
      severity: "high",
      testOnly: false,
      evidence: [],
      identity: { device: 1, inode: 2, size: 3, modifiedSec: 0, modifiedNsec: 0, changedSec: 0, changedNsec: 0 },
      changedDuringRead: false,
      archiveEntry: null,
      origin: null,
    },
    provenance: {
      channel: "web",
      downloadUrl: "https://cdn.example.com/invoice.zip",
      referrerUrl: "https://shop.example.com/download",
      emailFrom: null,
      savedBy: "Safari",
      arrivedAtMs: T0,
      createdAtMs: T0,
      modifiedAtMs: T0,
    },
    chain: [],
    outcome: { type: "quarantined", itemId: "q1", processTerminated: false },
    updatedAtMs: T0 + 2500,
    ...overrides,
  };
}

describe("příběh útoku", () => {
  it("vypráví stažení, zachycení a izolaci i s rychlostí zásahu", () => {
    const s = story();
    expect(storySummary(s)).toMatch(/^Soubor invoice\.zip přišel .* z internetu ze stránky shop\.example\.com \(Safari\)\. AntiShield ho za 2 s zachytil a izoloval v karanténě\.$/);
    const steps = storySteps(s);
    expect(steps.map((x) => x.id)).toEqual(["origin", "disk", "detect", "outcome"]);
    expect(steps[0]?.lines).toContain("Ze stránky shop.example.com");
    expect(steps[2]?.lines).toContain("2 s po příchodu souboru");
    expect(steps[3]?.tone).toBe("good");
    expect(storyAdvice(s)[0]).toMatch(/Změňte hesla/);
  });

  it("u spuštěného programu ukáže, kdo ho spustil", () => {
    const s = story({
      source: "program",
      chain: [
        { pid: 40, name: "invoice", path: "/tmp/invoice", startedAtMs: T0 + 1000 },
        { pid: 30, name: "Finder", path: null, startedAtMs: null },
        { pid: 1, name: "launchd", path: null, startedAtMs: null },
      ],
      outcome: { type: "quarantined", itemId: "q1", processTerminated: true },
    });
    const launch = storySteps(s).find((x) => x.id === "launch");
    expect(launch?.lines).toEqual(["Spustil ho Finder", "Řetěz spuštění: launchd → Finder → invoice"]);
    expect(storySummary(s)).toContain("program ukončil a izoloval v karanténě");
  });

  it("nic si nedomýšlí, když původ chybí, a pozná testovací soubor", () => {
    const s = story({
      finding: { ...story().finding, testOnly: true, severity: "test_only" },
      provenance: { channel: "unknown", downloadUrl: null, referrerUrl: null, emailFrom: null, savedBy: null, arrivedAtMs: null, createdAtMs: null, modifiedAtMs: null },
      outcome: { type: "reported" },
    });
    expect(storySummary(s)).toBe(
      `Testovací soubor, ne skutečná hrozba. Odkud se soubor invoice.zip vzal, systém nezaznamenal. AntiShield ho ${new Date(T0 + 2000).toLocaleString("cs-CZ", { day: "numeric", month: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" })} zachytil a čeká na vaše rozhodnutí.`,
    );
    expect(storySteps(s)[0]?.lines[0]).toMatch(/nezapsal/);
    expect(storyAdvice(s)).toEqual(["Nic nehrozí: testovací soubor jen ověřil, že ochrana zasahuje."]);
  });

  it("příloha e-mailu jmenuje odesílatele a radí ho varovat", () => {
    const s = story({
      provenance: { ...story().provenance, channel: "email", downloadUrl: null, referrerUrl: null, emailFrom: "Eva <eva@example.com>", savedBy: "Mail" },
      outcome: { type: "reported" },
    });
    expect(storySummary(s)).toContain("jako příloha e-mailu od Eva <eva@example.com>");
    expect(storyAdvice(s)).toContain("Odesílateli dejte vědět jinou cestou; jeho schránka může být napadená.");
    expect(storyAdvice(s)[0]).toMatch(/^Vyčistěte nález/);
  });

  it("program v aplikaci pojmenuje celou aplikaci a složku, kde leží", () => {
    const s = story({ finding: { ...story().finding, path: "/Users/eva/Downloads/invoice.pdf.app/Contents/MacOS/loader" } });
    expect(storySummary(s)).toMatch(/^Soubor invoice\.pdf\.app přišel/);
    expect(storySteps(s).find((x) => x.id === "disk")?.title).toBe("Uloženo ve složce Downloads");
    const mail = story({ finding: { ...story().finding, path: "/Users/eva/Library/Mail/V10/x/Attachments/1/2/a.pdf" } });
    expect(storySteps(mail).find((x) => x.id === "disk")?.title).toBe("Uloženo v poště Apple Mail");
  });

  it("pomocné funkce", () => {
    expect(hostOf("https://a.example.com/x?y")).toBe("a.example.com");
    expect(hostOf(null)).toBeNull();
    expect(shortDuration(1500)).toBe("2 s");
    expect(shortDuration(5 * 60_000)).toBe("5 min");
    expect(shortDuration(3 * 3_600_000 + 10 * 60_000)).toBe("3 h 10 min");
    expect(shortDuration(3 * 86_400_000)).toBe("3 dny");
    expect(storyFor([story()], "/Users/eva/Downloads/invoice.zip", "ab".repeat(32))?.id).toBe("s1");
    expect(storyFor([story()], "/other")).toBeUndefined();
  });
});
