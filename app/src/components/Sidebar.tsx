import type { EngineInfo } from "../lib/types";

export type Screen =
  | "overview"
  | "scan"
  | "results"
  | "events"
  | "realtime"
  | "quarantine"
  | "systemcare"
  | "about";

const MAIN: { id: Screen; label: string }[] = [
  { id: "overview", label: "Přehled" },
  { id: "scan", label: "Kontrola souborů" },
  { id: "results", label: "Výsledky" },
  { id: "events", label: "Události" },
];

const PLANNED: { id: Screen; label: string }[] = [
  { id: "realtime", label: "Ochrana v reálném čase" },
  { id: "quarantine", label: "Karanténa" },
  { id: "systemcare", label: "System Care" },
];

export function Sidebar({
  screen,
  onNavigate,
  info,
  scanRunning,
}: {
  screen: Screen;
  onNavigate: (screen: Screen) => void;
  info: EngineInfo | null;
  scanRunning: boolean;
}) {
  const item = (entry: { id: Screen; label: string }, planned = false) => (
    <li key={entry.id}>
      <button
        type="button"
        className={`nav-item${screen === entry.id ? " is-active" : ""}${planned ? " is-planned" : ""}`}
        aria-current={screen === entry.id ? "page" : undefined}
        onClick={() => onNavigate(entry.id)}
      >
        <span>{entry.label}</span>
        {entry.id === "scan" && scanRunning ? <span className="nav-badge">běží</span> : null}
      </button>
    </li>
  );

  return (
    <aside className="sidebar">
      <div className="brand">
        <svg viewBox="0 0 40 44" className="brand-mark" aria-hidden="true">
          <path d="M20 2 L37 8.5 V21 C37 31 30 38.5 20 42 C10 38.5 3 31 3 21 V8.5 Z" />
          <path d="M20 8 L31 12.2 V21 C31 28 26.5 33 20 35.6 Z" className="brand-mark-inner" />
        </svg>
        <div>
          <p className="brand-name">H&amp;H AntiShield</p>
          <p className="brand-sub">Ruční kontrola souborů</p>
        </div>
      </div>

      <nav aria-label="Hlavní">
        <ul className="nav">{MAIN.map((e) => item(e))}</ul>
        <p className="nav-group">Plánováno pro další verze</p>
        <ul className="nav">{PLANNED.map((e) => item(e, true))}</ul>
        <ul className="nav">{item({ id: "about", label: "O aplikaci" })}</ul>
      </nav>

      <div className="sidebar-foot">
        <p>Verze 0.1.0</p>
        {info ? (
          <p>
            Pravidla {info.rulePack.version}
            {info.rulePack.testPack ? " (testovací)" : ""}
          </p>
        ) : (
          <p>Pravidla nejsou načtená</p>
        )}
      </div>
    </aside>
  );
}
