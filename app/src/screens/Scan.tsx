import { Icon, type IconName } from "../components/Icon";
import type { Screen } from "../components/Sidebar";
import { displayPath, formatBytes, formatCount, formatDuration } from "../lib/format";
import type { PresetScan } from "../lib/types";
import type { AntiShield } from "../lib/useAntiShield";

const PRESETS: { kind: PresetScan; icon: IconName; title: string; text: string }[] = [
  {
    kind: "quick",
    icon: "bolt",
    title: "Rychlá kontrola",
    text: "Běžící programy, položky spouštěné po přihlášení, Stažené soubory a Plocha. Pár minut.",
  },
  {
    kind: "full",
    icon: "shield",
    title: "Úplná kontrola",
    text: "Celá domovská složka a nainstalované aplikace. Trvá déle, běží na pozadí.",
  },
];

export function Scan({ app, onNavigate }: { app: AntiShield; onNavigate: (s: Screen) => void }) {
  const { scan, selection } = app;
  const ready = app.protection?.level !== "notReady";

  if (scan.running) {
    const p = scan.progress;
    return (
      <div className="screen">
        <h1>Kontrola běží</h1>
        {scan.roots.length ? <p className="muted roots">{scan.roots.join(", ")}</p> : null}
        <div className="progress-track" role="progressbar" aria-label="Kontrola běží" aria-busy="true">
          <span />
        </div>
        <dl className="stats">
          <div>
            <dt>Zkontrolováno</dt>
            <dd>{formatCount(p?.filesScanned ?? 0, "soubor", "soubory", "souborů")}</dd>
          </div>
          <div>
            <dt>Přečtená data</dt>
            <dd>{formatBytes(p?.bytesScanned ?? 0)}</dd>
          </div>
          <div>
            <dt>Přeskočeno</dt>
            <dd>{(p?.itemsSkipped ?? 0).toLocaleString("cs-CZ")}</dd>
          </div>
          <div>
            <dt>Nálezy</dt>
            <dd className={(p?.findings ?? 0) > 0 ? "tone-text-alert" : undefined}>{p?.findings ?? 0}</dd>
          </div>
          <div>
            <dt>Čas</dt>
            <dd>{formatDuration(p?.elapsedMs ?? 0)}</dd>
          </div>
        </dl>
        {p?.currentPath ? (
          <p className="current-path" title={displayPath(p.currentPath)}>
            {displayPath(p.currentPath)}
          </p>
        ) : null}
        {scan.liveFindings.length ? (
          <ul className="live-findings">
            {scan.liveFindings.map((f, i) => (
              <li key={`${f.path}-${f.ruleId}-${i}`}>
                <strong>{f.ruleName}</strong> <span className="muted">{displayPath(f.path)}</span>
              </li>
            ))}
          </ul>
        ) : null}
        <div className="actions">
          <button type="button" className="btn-secondary" onClick={() => void app.cancel()}>
            Zrušit kontrolu
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="screen">
      <h1>Kontrola počítače</h1>
      <p className="lede">
        Kontrola soubory jen čte a porovná je s pravidly. Nalezené hrozby pak jedním kliknutím
        vyčistíte: přesunou se do karantény, odkud je jde obnovit.
      </p>

      <div className="preset-grid">
        {PRESETS.map((preset) => (
          <button
            key={preset.kind}
            type="button"
            className="preset"
            disabled={!ready}
            onClick={() => void app.startPreset(preset.kind)}
          >
            <span className="icon-tile big">
              <Icon name={preset.icon} size={26} />
            </span>
            <span className="preset-title">{preset.title}</span>
            <span className="preset-text">{preset.text}</span>
            <span className="preset-go">
              Spustit <Icon name="chevron" size={16} />
            </span>
          </button>
        ))}
        <div className="preset custom">
          <span className="icon-tile big">
            <Icon name="folder" size={26} />
          </span>
          <span className="preset-title">Vlastní kontrola</span>
          <span className="preset-text">Vyberte konkrétní složky nebo soubory.</span>
          <span className="actions">
            <button type="button" className="btn-secondary" disabled={!ready} onClick={() => void app.pick("folders")}>
              Složky
            </button>
            <button type="button" className="btn-secondary" disabled={!ready} onClick={() => void app.pick("files")}>
              Soubory
            </button>
          </span>
        </div>
      </div>

      {selection ? (
        <section className="panel selection" aria-labelledby="selection-title">
          <h2 id="selection-title">Ke kontrole</h2>
          <ul>
            {selection.paths.map((path) => (
              <li key={path}>{path}</li>
            ))}
          </ul>
          <div className="actions">
            <button type="button" className="btn-primary" disabled={!ready} onClick={() => void app.start()}>
              Spustit kontrolu
            </button>
            <button type="button" className="btn-link" onClick={app.clearSelection}>
              Zrušit výběr
            </button>
          </div>
        </section>
      ) : null}

      {app.summary ? (
        <p>
          Poslední kontrola je hotová.{" "}
          <button type="button" className="btn-link" onClick={() => onNavigate("results")}>
            Zobrazit výsledky
          </button>
        </p>
      ) : null}

      <section className="panel limits" aria-labelledby="limits-title">
        <h2 id="limits-title">Co kontrola dělá</h2>
        <ul>
          <li>Porovná soubory s podepsanou sadou pravidel: otisky SHA-256, bajtové vzory a pravidla YARA.</li>
          <li>Rozbalí archivy ZIP (s ochranou proti „zip bombám“); šifrované a vnořené archivy jen označí.</li>
          <li>Nesleduje symbolické odkazy, nestahuje soubory z iCloudu ani OneDrivu a přeskočí síťové disky.</li>
          <li>Pravidla YARA dostanou soubory do 32 MB; větší se zkontrolují otisky a jsou ve výsledku označené.</li>
        </ul>
      </section>
    </div>
  );
}
