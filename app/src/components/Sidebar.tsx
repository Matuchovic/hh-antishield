import logo from "../assets/hh-logo.png";
import { platformName } from "../lib/format";
import type { EngineInfo, ProtectionLevel } from "../lib/types";
import { Icon, type IconName } from "./Icon";

export type Screen =
  | "overview"
  | "scan"
  | "results"
  | "events"
  | "realtime"
  | "quarantine"
  | "systemcare"
  | "about";

interface Entry {
  id: Screen;
  label: string;
  icon: IconName;
  planned?: boolean;
}

const ENTRIES: Entry[] = [
  { id: "overview", label: "Přehled", icon: "home" },
  { id: "scan", label: "Kontrola souborů", icon: "search" },
  { id: "results", label: "Výsledky", icon: "results" },
  { id: "events", label: "Události", icon: "clock" },
  { id: "realtime", label: "Ochrana v reálném čase", icon: "shield", planned: true },
  { id: "quarantine", label: "Karanténa", icon: "box", planned: true },
  { id: "systemcare", label: "System Care", icon: "gauge", planned: true },
  { id: "about", label: "O aplikaci", icon: "info" },
];

const LEVEL: Record<ProtectionLevel, { text: string; tone: string }> = {
  protected: { text: "Ochrana aktivní", tone: "good" },
  manualScanOnly: { text: "Ruční kontrola připravená", tone: "caution" },
  notReady: { text: "Kontrola není připravená", tone: "alert" },
};

export function Sidebar({
  screen,
  onNavigate,
  info,
  level,
  scanRunning,
}: {
  screen: Screen;
  onNavigate: (screen: Screen) => void;
  info: EngineInfo | null;
  level: ProtectionLevel | null;
  scanRunning: boolean;
}) {
  const status = level ? LEVEL[level] : null;
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-logo">
          <img src={logo} alt="" draggable={false} />
          <span className="logo-shine" />
        </div>
        <p className="brand-name">H&amp;H AntiShield</p>
        <p className="brand-sub">Ruční kontrola souborů</p>
      </div>

      <nav aria-label="Hlavní">
        <ul className="nav">
          {ENTRIES.map((entry) => (
            <li key={entry.id}>
              <button
                type="button"
                className={`nav-item${screen === entry.id ? " is-active" : ""}${entry.planned ? " is-planned" : ""}`}
                aria-current={screen === entry.id ? "page" : undefined}
                onClick={() => onNavigate(entry.id)}
              >
                <Icon name={entry.icon} />
                <span>{entry.label}</span>
                {entry.id === "scan" && scanRunning ? <span className="nav-badge">běží</span> : null}
                {entry.planned ? <span className="nav-tag">plán</span> : null}
              </button>
            </li>
          ))}
        </ul>
      </nav>

      <div className={`sidebar-foot tone-${status?.tone ?? "off"}`}>
        <p className="foot-status">
          <span className="dot" aria-hidden="true" />
          {status?.text ?? "Načítám stav…"}
        </p>
        <p>Verze 0.1.0{info ? `, ${platformName(info.platform)}` : ""}</p>
        <p>
          {info
            ? `Pravidla ${info.rulePack.version}${info.rulePack.testPack ? " (testovací)" : ""}`
            : "Pravidla nejsou načtená"}
        </p>
      </div>
    </aside>
  );
}
