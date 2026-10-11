import { describe, expect, it } from "vitest";
import {
  COMPONENT_LABELS,
  describeEvidence,
  describeState,
  formatBytes,
  formatCount,
  headline,
  platformName,
} from "./format";
import type { ComponentKind, ComponentState, ComponentStatus, ProtectionLevel } from "./types";

const KINDS = Object.keys(COMPONENT_LABELS) as ComponentKind[];
const STATES: ComponentState[] = [
  { type: "notImplemented" },
  { type: "disabled" },
  { type: "running", verifiedAtMs: 0 },
  { type: "degraded", reason: "x" },
  { type: "failed", reason: "x" },
];

function components(overrides: Partial<Record<ComponentKind, ComponentState>>): ComponentStatus[] {
  return KINDS.map((kind) => ({ kind, state: overrides[kind] ?? { type: "notImplemented" } }));
}

describe("headline", () => {
  it("version 0.1 never claims protection", () => {
    const running: ComponentState = { type: "running", verifiedAtMs: 0 };
    const h = headline(
      "manualScanOnly",
      components({ detectionEngine: running, rulePack: running, onDemandScan: running }),
    );
    expect(h.title).toBe("Ruční kontrola je připravená");
    expect(h.title).not.toMatch(/chráněn/i);
    expect(h.detail).toMatch(/není součástí verze 0\.1/);
  });

  it("never shows 'Ochrana běží' unless real-time protection runs", () => {
    const levels: ProtectionLevel[] = ["notReady", "manualScanOnly", "protected"];
    for (const level of levels) {
      for (const state of STATES) {
        const h = headline(level, components({ realTimeProtection: state }));
        if (h.title === "Ochrana běží") {
          expect(state.type).toBe("running");
        }
      }
    }
  });

  it("explains why the scan is not ready", () => {
    const h = headline(
      "notReady",
      components({ rulePack: { type: "failed", reason: "rule pack signature is invalid" } }),
    );
    expect(h.tone).toBe("alert");
    expect(h.detail).toContain("Sada pravidel");
  });
});

describe("texts", () => {
  it("describes component states without claiming activity", () => {
    expect(describeState({ type: "notImplemented" })).toBe("Není ve verzi 0.1");
    expect(describeState({ type: "degraded", reason: "self-test has not run yet" })).toBe(
      "Omezeno: self-test zatím neproběhl",
    );
  });

  it("explains evidence", () => {
    expect(describeEvidence({ type: "sha256Match", digestHex: "ab" }, "R-1")).toContain("SHA-256");
    expect(describeEvidence({ type: "bytePattern", offset: 10, length: 30 }, "R-2")).toContain(
      "pozici 10",
    );
    expect(describeEvidence({ type: "eicarStandard" }, "R-3")).toContain("EICAR");
  });

  it("formats numbers in Czech", () => {
    expect(formatCount(1, "soubor", "soubory", "souborů")).toBe("1 soubor");
    expect(formatCount(3, "soubor", "soubory", "souborů")).toBe("3 soubory");
    expect(formatCount(5, "soubor", "soubory", "souborů")).toBe("5 souborů");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1_500_000)).toMatch(/^1,5\sMB$/);
  });
});

describe("platformName", () => {
  it("pojmenuje platformy srozumitelně", () => {
    expect(platformName("macos-aarch64")).toBe("macOS Apple Silicon");
    expect(platformName("macos-x86_64")).toBe("macOS Intel");
    expect(platformName("windows-x86_64")).toBe("Windows x64");
  });
});
