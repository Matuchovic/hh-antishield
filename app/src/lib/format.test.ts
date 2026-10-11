import { describe, expect, it } from "vitest";
import {
  COMPONENT_LABELS,
  describeAuditEvent,
  describeError,
  describeEvidence,
  describeState,
  displayPath,
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
  it("manual scan never claims protection and says why", () => {
    const running: ComponentState = { type: "running", verifiedAtMs: 0 };
    const h = headline(
      "manualScanOnly",
      components({ detectionEngine: running, rulePack: running, onDemandScan: running, realTimeProtection: { type: "disabled" } }),
    );
    expect(h.title).toBe("Ruční kontrola je připravená");
    expect(h.title).not.toMatch(/chráněn|hlídaný/i);
    expect(h.detail).toMatch(/vypnuté/);
  });

  it("monitored says watched, never protected, and admits no blocking", () => {
    const running: ComponentState = { type: "running", verifiedAtMs: 0 };
    const h = headline("monitored", components({ realTimeProtection: running, updates: running }), "Mac");
    expect(h.title).toBe("Váš Mac je hlídaný");
    expect(h.title).not.toMatch(/chráněn/i);
    expect(h.detail).toMatch(/neblokujeme/);
  });

  it("never claims protection or watching unless real-time protection runs", () => {
    const levels: ProtectionLevel[] = ["notReady", "manualScanOnly", "monitored", "protected"];
    for (const level of levels) {
      for (const state of STATES) {
        const h = headline(level, components({ realTimeProtection: state }));
        if (/chráněn|hlídaný/.test(h.title)) {
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

  it("explains update failures with the technical reason", () => {
    expect(describeError({ code: "update", message: "Read-only file system (os error 30)" })).toMatch(
      /^Aktualizaci se nepodařilo .*\(Read-only file system \(os error 30\)\)$/,
    );
    expect(describeError({ code: "update_location", message: "x" })).toMatch(/složce Aplikace/);
  });

  it("hides the Windows verbatim path prefix", () => {
    expect(displayPath("\\\\?\\C:\\Users\\eva\\a.exe")).toBe("C:\\Users\\eva\\a.exe");
    expect(displayPath("\\\\?\\UNC\\srv\\share\\a.exe")).toBe("\\\\srv\\share\\a.exe");
    expect(displayPath("/Users/eva/a.app")).toBe("/Users/eva/a.app");
  });

  it("describes a finished scan without a dangling separator", () => {
    const base = { seq: 1, tsMs: 0, kind: "scan_finished" };
    expect(describeAuditEvent({ ...base, data: { filesScanned: 2, findings: 1 } }).detail).toBe("2 soubory, 1 nález");
    expect(
      describeAuditEvent({ ...base, data: { outcome: { type: "completed" }, filesScanned: 5, findings: 0 } }).detail,
    ).toMatch(/^[^:]+: 5 souborů, 0 nálezů$/);
  });

  it("explains an audit integrity issue and whether it was sealed", () => {
    const base = { seq: 1, tsMs: 0, kind: "audit_integrity_issue" };
    const chain = describeAuditEvent({
      ...base,
      data: { detail: "audit-000001.jsonl: chain broken at seq 3", sealed: true },
    });
    expect(chain.title).toBe("Problém s integritou auditu");
    expect(chain.detail).toBe("Záznamy na sebe nenavazují (souběžný zápis nebo úprava); uzavřeno, zápis pokračuje v novém souboru");
    // Záznam ze starší verze (bez uzavření) netvrdí, že je soubor uzavřený.
    expect(
      describeAuditEvent({ ...base, data: { detail: "audit-000001.jsonl: the last record is truncated" } }).detail,
    ).toBe("Useknutý zápis, nejspíš po nečekaném vypnutí");
  });
});

describe("platformName", () => {
  it("pojmenuje platformy srozumitelně", () => {
    expect(platformName("macos-aarch64")).toBe("macOS Apple Silicon");
    expect(platformName("macos-x86_64")).toBe("macOS Intel");
    expect(platformName("windows-x86_64")).toBe("Windows x64");
  });
});
