import { storyFor } from "../lib/story";
import { Icon } from "../components/Icon";
import type { Screen } from "../components/Sidebar";
import {
  SKIP_LABELS,
  describeError,
  describeEvidence,
  describeOrigin,
  describeOutcome,
  displayPath,
  findingNote,
  formatBytes,
  formatCount,
  formatDateTime,
  formatDuration,
} from "../lib/format";
import type { Finding, RemediationReport } from "../lib/types";
import type { AntiShield } from "../lib/useAntiShield";

function CleanState({ state }: { state: "busy" | RemediationReport | undefined }) {
  if (state === undefined) return null;
  if (state === "busy") return <p className="clean-state">Čistím…</p>;
  if (state.quarantined) {
    const extra = [
      state.processTerminated ? "proces ukončen" : null,
      state.startupDisabled ? "položka po spuštění vypnuta" : null,
    ].filter(Boolean);
    return (
      <p className="clean-state tone-text-good">
        <Icon name="check" size={16} /> Přesunuto do karantény{extra.length ? `, ${extra.join(", ")}` : ""}.
      </p>
    );
  }
  const problem = state.problems[0] ?? "";
  const code = problem.split(":")[0] ?? "";
  return (
    <p className="clean-state tone-text-alert">
      Nepovedlo se: {describeError({ code, message: problem })}
    </p>
  );
}

export function Results({ app, onNavigate }: { app: AntiShield; onNavigate: (s: Screen) => void }) {
  const summary = app.summary;
  if (!summary) {
    return (
      <div className="screen">
        <h1>Výsledky</h1>
        <p className="muted">Zatím žádná dokončená kontrola.</p>
        <button type="button" className="btn-primary" onClick={() => onNavigate("scan")}>
          Spustit kontrolu
        </button>
      </div>
    );
  }
  const sources = summary.rulePack.sources;
  const pending = summary.findings.filter((f) => app.cleaning[f.path] === undefined);
  const uniquePending = [...new Set(pending.map((f) => f.path))];
  const tone = summary.findings.length ? "alert" : summary.outcome.type === "completed" ? "good" : "caution";

  // Nálezy seskupené podle souboru: vyčištění se týká celého souboru.
  const byFile = new Map<string, Finding[]>();
  for (const f of summary.findings) byFile.set(f.path, [...(byFile.get(f.path) ?? []), f]);

  return (
    <div className="screen">
      <h1>Výsledky</h1>
      <section className={`result-banner tone-${tone}`}>
        <p className="big-line">
          {describeOutcome(summary.outcome)}:{" "}
          {summary.findings.length ? formatCount(byFile.size, "soubor s nálezem", "soubory s nálezem", "souborů s nálezem") : "bez nálezu"}
        </p>
        <p className="muted">
          {formatDateTime(summary.finishedAtMs)}, trvala {formatDuration(summary.finishedAtMs - summary.startedAtMs)}.{" "}
          {formatCount(summary.filesScanned, "soubor", "soubory", "souborů")}, {formatBytes(summary.bytesScanned)}.
        </p>
        {uniquePending.length ? (
          <div className="actions">
            <button type="button" className="btn-danger" onClick={() => void app.remediate(uniquePending)}>
              <Icon name="sparkle" size={18} /> Vyčistit vše ({uniquePending.length})
            </button>
            <span className="muted">Soubory se přesunou do karantény; obnovit je jde kdykoli.</span>
          </div>
        ) : null}
      </section>

      {byFile.size ? (
        <section aria-labelledby="findings-title">
          <h2 id="findings-title">Nálezy</h2>
          <ul className="findings">
            {[...byFile.entries()].map(([path, findings]) => {
              const first = findings[0] as Finding;
              const note = findingNote(first);
              const origin = describeOrigin(first.origin);
              const state = app.cleaning[path];
              const story = storyFor(app.stories, path, first.sha256);
              return (
                <li key={path} className={`finding${first.testOnly ? " is-test" : ""}${state && state !== "busy" && state.quarantined ? " is-clean" : ""}`}>
                  <div className="finding-head">
                    <p className="finding-path">{displayPath(path)}</p>
                    <span className="finding-actions">
                      {story ? (
                        <button type="button" className="btn-secondary small" onClick={() => app.openStory(story.id)}>
                          Příběh útoku
                        </button>
                      ) : null}
                      {state === undefined ? (
                        <button type="button" className="btn-danger small" onClick={() => void app.remediate([path])}>
                          Vyčistit
                        </button>
                      ) : null}
                    </span>
                  </div>
                  {findings.map((f, i) => (
                    <div key={`${f.ruleId}-${i}`} className="finding-rule-block">
                      <p className="finding-rule">
                        {f.ruleName} <span className="muted">{f.ruleId}</span>
                        {f.archiveEntry ? <span className="chip">v archivu: {f.archiveEntry}</span> : null}
                      </p>
                      <p>
                        <strong>Proč: </strong>
                        {f.evidence.map((e) => describeEvidence(e, f.ruleId, sources)).join(" ")}
                      </p>
                      {f.ruleDescription ? <p className="muted">{f.ruleDescription}</p> : null}
                    </div>
                  ))}
                  {origin ? <p className="finding-note">{origin}</p> : null}
                  {note ? <p className="finding-note">{note}</p> : null}
                  <CleanState state={state} />
                  <p className="hash">SHA-256 {first.sha256}</p>
                </li>
              );
            })}
          </ul>
        </section>
      ) : null}

      {summary.skippedTotal ? (
        <section className="panel" aria-labelledby="skipped-title">
          <h2 id="skipped-title">Nezkontrolováno: {formatCount(summary.skippedTotal, "položka", "položky", "položek")}</h2>
          <table className="table">
            <tbody>
              {summary.skippedByReason.map((c) => (
                <tr key={c.reason}>
                  <th scope="row">{SKIP_LABELS[c.reason] ?? c.reason}</th>
                  <td>{c.count.toLocaleString("cs-CZ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <details>
            <summary>Ukázka přeskočených položek</summary>
            <ul className="skipped">
              {summary.skippedSample.map((s, i) => (
                <li key={`${s.path}-${i}`}>
                  <span>{displayPath(s.path)}</span> <span className="muted">{SKIP_LABELS[s.reason.type]}</span>
                </li>
              ))}
            </ul>
          </details>
        </section>
      ) : null}

      {summary.archivesNotInspected ? (
        <p className="notice">
          {formatCount(summary.archivesNotInspected, "archiv nešlo", "archivy nešlo", "archivů nešlo")} zkontrolovat celý
          (šifrovaný, příliš velký, vnořený nebo jiný formát než ZIP).
        </p>
      ) : null}
      {summary.yaraIncomplete ? (
        <p className="notice">
          {formatCount(summary.yaraIncomplete, "soubor byl zkontrolován", "soubory byly zkontrolovány", "souborů bylo zkontrolováno")}{" "}
          jen otisky a vzory, bez pravidel YARA (větší než 32 MB nebo kontrola trvala příliš dlouho).
        </p>
      ) : null}
      <p className="notice">
        Sada pravidel {summary.rulePack.version}: {formatCount(summary.rulePack.yaraRuleCount, "pravidlo", "pravidla", "pravidel")} YARA
        {summary.rulePack.testPack ? " (zatím jen testovací sada, skutečná pravidla přijdou s první aktualizací)" : ""}.
      </p>
    </div>
  );
}
