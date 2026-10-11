import { Icon } from "../components/Icon";
import type { Screen } from "../components/Sidebar";
import { Toggle } from "../components/Toggle";
import { describeState, formatDateTime, stateTone } from "../lib/format";
import type { DetectionAction } from "../lib/types";
import type { AntiShield } from "../lib/useAntiShield";

function actionText(action: DetectionAction): string {
  switch (action.type) {
    case "quarantined":
      return "Přesunuto do karantény";
    case "detected":
      return "Zachyceno, čeká na vyčištění";
    case "failed":
      return "Izolace se nepovedla";
  }
}

export function Protection({ app, onNavigate }: { app: AntiShield; onNavigate: (s: Screen) => void }) {
  const { settings, runtime, protection } = app;
  const realtime = protection?.components.find((c) => c.kind === "realTimeProtection")?.state;
  const pendingDetections = runtime?.detections.filter((d) => d.action.type !== "quarantined") ?? [];

  return (
    <div className="screen">
      <h1>Ochrana v reálném čase</h1>
      <p className="lede">
        AntiShield hlídá vybrané složky. Každý nový nebo změněný soubor zkontroluje během pár sekund a
        škodlivý hned přesune do karantény, obvykle dřív, než ho stihnete otevřít. Spouštění programů
        mimo hlídané složky zatím neblokuje.
      </p>

      <section className={`panel protection-state tone-${realtime ? stateTone(realtime) : "off"}`}>
        <div className="panel-head">
          <h2>
            <span className="dot" aria-hidden="true" /> {realtime ? describeState(realtime) : "Načítám…"}
          </h2>
          {runtime?.watchingSinceMs ? <span className="muted">od {formatDateTime(runtime.watchingSinceMs)}</span> : null}
        </div>
        {settings ? (
          <div className="toggle-list">
            <Toggle
              label="Hlídat složky"
              detail="Kontrola nových a změněných souborů na pozadí."
              checked={settings.protectionEnabled}
              onChange={(value) => void app.saveSettings({ protectionEnabled: value })}
            />
            <Toggle
              label="Automaticky izolovat hrozby"
              detail="Nález se hned přesune do karantény; obnovit ho jde kdykoli."
              checked={settings.autoQuarantine}
              onChange={(value) => void app.saveSettings({ autoQuarantine: value })}
            />
          </div>
        ) : null}
      </section>

      <section className="panel" aria-labelledby="watched-title">
        <div className="panel-head">
          <h2 id="watched-title">Hlídané složky</h2>
          <button type="button" className="btn-link" onClick={() => onNavigate("settings")}>
            Upravit v Nastavení
          </button>
        </div>
        {runtime?.watched.length ? (
          <ul className="path-list">
            {runtime.watched.map((path) => (
              <li key={path}>
                <Icon name="folder" size={18} /> {path}
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">Žádná složka se nehlídá.</p>
        )}
        {runtime?.watchError ? <p className="notice tone-alert">{runtime.watchError}</p> : null}
      </section>

      <section className="panel" aria-labelledby="detections-title">
        <h2 id="detections-title">Zachycené hrozby</h2>
        {runtime?.detections.length ? (
          <ul className="detections">
            {runtime.detections.map((d, i) => (
              <li key={`${d.atMs}-${i}`} className={d.action.type === "quarantined" ? "tone-good" : "tone-alert"}>
                <span className="dot" aria-hidden="true" />
                <span className="detection-main">
                  <strong>{d.finding.ruleName}</strong>
                  <span className="muted">{d.finding.path}</span>
                </span>
                <span className="detection-side">
                  <span>{actionText(d.action)}</span>
                  <time className="muted">{formatDateTime(d.atMs)}</time>
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">Zatím nic. Až hlídání něco zachytí, uvidíte to tady a přijde oznámení.</p>
        )}
        {pendingDetections.length ? (
          <div className="actions">
            <button
              type="button"
              className="btn-danger"
              onClick={() => void app.remediate(pendingDetections.map((d) => d.finding.path))}
            >
              Vyčistit zachycené ({pendingDetections.length})
            </button>
          </div>
        ) : null}
      </section>
    </div>
  );
}
