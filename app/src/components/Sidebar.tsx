import brandLogo from "../assets/hh-antishield-logo.png";
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
  | "care"
  | "fleet"
  | "settings"
  | "about";

interface Entry {
  id: Screen;
  label: string;
  icon: IconName;
}

const ENTRIES: Entry[] = [
  { id: "overview", label: "Přehled", icon: "home" },
  { id: "scan", label: "Kontrola počítače", icon: "search" },
  { id: "results", label: "Výsledky", icon: "results" },
  { id: "realtime", label: "Ochrana v reálném čase", icon: "shield" },
  { id: "quarantine", label: "Karanténa", icon: "box" },
  { id: "systemcare", label: "Bezpečnost systému", icon: "gauge" },
  { id: "care", label: "Čištění a zrychlení", icon: "sparkle" },
  { id: "fleet", label: "Firemní Macy", icon: "laptop" },
  { id: "events", label: "Události", icon: "clock" },
  { id: "settings", label: "Nastavení", icon: "sliders" },
  { id: "about", label: "O aplikaci", icon: "info" },
];

const LEVEL: Record<ProtectionLevel, { text: string; tone: string }> = {
  protected: { text: "Ochrana aktivní", tone: "good" },
  monitored: { text: "Hlídání běží", tone: "good" },
  manualScanOnly: { text: "Ruční kontrola připravená", tone: "caution" },
  notReady: { text: "Kontrola není připravená", tone: "alert" },
};

export function Sidebar({
  screen,
  onNavigate,
  info,
  level,
  scanRunning,
  quarantineCount,
  fleetAdmin,
  managedBy,
}: {
  screen: Screen;
  onNavigate: (screen: Screen) => void;
  info: EngineInfo | null;
  level: ProtectionLevel | null;
  scanRunning: boolean;
  quarantineCount: number;
  /** Tento Mac spravuje firemní Macy (zobrazí se jejich obrazovka). */
  fleetAdmin: boolean;
  /** Firma, která tento Mac spravuje. */
  managedBy: string | null;
}) {
  const status = level ? LEVEL[level] : null;
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-logo">
          <img src={brandLogo} alt="H&H AntiShield – Antivirus & System Protection" draggable={false} />
          <span className="logo-shine" />
        </div>
      </div>

      <nav aria-label="Hlavní">
        <ul className="nav">
          {ENTRIES.filter((entry) => entry.id !== "fleet" || fleetAdmin).map((entry) => (
            <li key={entry.id}>
              <button
                type="button"
                className={`nav-item${screen === entry.id ? " is-active" : ""}`}
                aria-current={screen === entry.id ? "page" : undefined}
                onClick={() => onNavigate(entry.id)}
              >
                <Icon name={entry.icon} />
                <span>{entry.label}</span>
                {entry.id === "scan" && scanRunning ? <span className="nav-badge">běží</span> : null}
                {entry.id === "quarantine" && quarantineCount > 0 ? (
                  <span className="nav-tag">{quarantineCount}</span>
                ) : null}
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
        {managedBy ? (
          <p className="foot-managed">
            <Icon name="building" size={14} />
            Spravuje {managedBy}
          </p>
        ) : null}
        <p>Verze {__APP_VERSION__}{info ? `, ${platformName(info.platform)}` : ""}</p>
        <p>
          {info
            ? `Pravidla ${info.rulePack.version}${info.rulePack.testPack ? " (testovací)" : ""}`
            : "Pravidla nejsou načtená"}
        </p>
      </div>
    </aside>
  );
}
