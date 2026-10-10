import { formatBytes, formatCount, formatDuration } from "../lib/format";
import type { AntiShield } from "../lib/useAntiShield";
import type { Screen } from "../components/Sidebar";

export function Scan({ app, onNavigate }: { app: AntiShield; onNavigate: (s: Screen) => void }) {
  const { scan, selection } = app;
  const ready = app.protection?.level !== "notReady";

  if (scan.running) {
    const p = scan.progress;
    return (
      <div className="screen">
        <h1>Kontrola běží</h1>
        <p className="muted">{scan.roots.join(", ")}</p>
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
            <dd className={(p?.findings ?? 0) > 0 ? "text-alert" : undefined}>{p?.findings ?? 0}</dd>
          </div>
          <div>
            <dt>Čas</dt>
            <dd>{formatDuration(p?.elapsedMs ?? 0)}</dd>
          </div>
        </dl>
        {p?.currentPath ? <p className="current-path" title={p.currentPath}>{p.currentPath}</p> : null}
        {scan.liveFindings.length ? (
          <ul className="live-findings">
            {scan.liveFindings.map((f, i) => (
              <li key={`${f.path}-${f.ruleId}-${i}`}>
                <strong>{f.ruleName}</strong> <span className="muted">{f.path}</span>
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
      <h1>Kontrola souborů</h1>
      <p className="lede">
        Vyberte složky nebo soubory. Aplikace je jen přečte a porovná s pravidly; nic nemaže ani
        nepřesouvá.
      </p>
      <div className="actions">
        <button type="button" className="btn-secondary" disabled={!ready} onClick={() => void app.pick("folders")}>
          Vybrat složky
        </button>
        <button type="button" className="btn-secondary" disabled={!ready} onClick={() => void app.pick("files")}>
          Vybrat soubory
        </button>
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
      ) : (
        <p className="muted">Zatím nic nevybráno.</p>
      )}

      {app.summary && !app.scan.running ? (
        <p>
          Poslední kontrola je hotová.{" "}
          <button type="button" className="btn-link" onClick={() => onNavigate("results")}>
            Zobrazit výsledky
          </button>
        </p>
      ) : null}

      <section className="panel limits" aria-labelledby="limits-title">
        <h2 id="limits-title">Co kontrola dělá a co ne</h2>
        <ul>
          <li>Porovná SHA-256 celých souborů a bajtové vzory s testovací sadou pravidel.</li>
          <li>Nesleduje symbolické odkazy, nestahuje soubory z iCloudu ani OneDrivu a přeskočí síťové disky.</li>
          <li>Archivy (ZIP, DMG a další) nerozbaluje; jejich obsah se nekontroluje.</li>
          <li>Soubory větší než 4 GB přeskočí a uvede je ve výsledku.</li>
        </ul>
      </section>
    </div>
  );
}
