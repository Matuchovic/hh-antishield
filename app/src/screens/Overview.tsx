import { ShieldStatus } from "../components/ShieldStatus";
import {
  COMPONENT_LABELS,
  describeAuditEvent,
  describeOutcome,
  describeState,
  formatCount,
  formatDateTime,
  formatTime,
  headline,
  stateTone,
} from "../lib/format";
import type { AntiShield } from "../lib/useAntiShield";
import type { Screen } from "../components/Sidebar";

export function Overview({ app, onNavigate }: { app: AntiShield; onNavigate: (s: Screen) => void }) {
  const { protection, summary, events } = app;
  if (!protection) {
    return <p className="muted">Načítám stav enginu…</p>;
  }
  const h = headline(protection.level, protection.components);
  const ready = protection.level !== "notReady";

  const startWith = async (kind: "folders" | "files") => {
    await app.pick(kind);
    onNavigate("scan");
  };

  return (
    <div className="overview">
      <section className={`hero tone-${h.tone}`} aria-labelledby="hero-title">
        <ShieldStatus components={protection.components} />
        <div className="hero-copy">
          <h1 id="hero-title">{h.title}</h1>
          <p className="hero-detail">{h.detail}</p>
          <div className="actions">
            <button type="button" className="btn-primary" disabled={!ready || app.scan.running} onClick={() => void startWith("folders")}>
              Zkontrolovat složky
            </button>
            <button type="button" className="btn-secondary" disabled={!ready || app.scan.running} onClick={() => void startWith("files")}>
              Zkontrolovat soubory
            </button>
          </div>
        </div>
      </section>

      <section className="panel components" aria-labelledby="components-title">
        <h2 id="components-title">Stav komponent</h2>
        <ul>
          {protection.components.map((c) => (
            <li key={c.kind} className={`component tone-${stateTone(c.state)}`}>
              <span className="dot" aria-hidden="true" />
              <span className="component-name">{COMPONENT_LABELS[c.kind]}</span>
              <span className="component-state">{describeState(c.state)}</span>
            </li>
          ))}
        </ul>
      </section>

      <section className="panel last-scan" aria-labelledby="last-scan-title">
        <h2 id="last-scan-title">Poslední kontrola</h2>
        {summary ? (
          <>
            <p className="big-line">{describeOutcome(summary.outcome)}</p>
            <p className="muted">{formatDateTime(summary.finishedAtMs)}</p>
            <p>
              {formatCount(summary.filesScanned, "soubor", "soubory", "souborů")},{" "}
              {formatCount(summary.findings.length, "nález", "nálezy", "nálezů")},{" "}
              {formatCount(summary.skippedTotal, "přeskočená položka", "přeskočené položky", "přeskočených položek")}
            </p>
            <button type="button" className="btn-link" onClick={() => onNavigate("results")}>
              Zobrazit výsledky
            </button>
          </>
        ) : (
          <p className="muted">Od spuštění aplikace zatím žádná kontrola neproběhla.</p>
        )}
      </section>

      <section className="panel recent" aria-labelledby="recent-title">
        <div className="panel-head">
          <h2 id="recent-title">Poslední události</h2>
          <button type="button" className="btn-link" onClick={() => onNavigate("events")}>
            Všechny události
          </button>
        </div>
        {events.length ? (
          <ol className="event-list">
            {events.slice(0, 6).map((event) => {
              const d = describeAuditEvent(event);
              return (
                <li key={event.seq}>
                  <time>{formatTime(event.tsMs)}</time>
                  <span>
                    {d.title}
                    {d.detail ? <span className="muted"> {d.detail}</span> : null}
                  </span>
                </li>
              );
            })}
          </ol>
        ) : (
          <p className="muted">Auditní log je prázdný.</p>
        )}
      </section>
    </div>
  );
}
