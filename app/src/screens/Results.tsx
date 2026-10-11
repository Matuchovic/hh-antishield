import {
  SKIP_LABELS,
  describeEvidence,
  describeOutcome,
  findingNote,
  formatBytes,
  formatCount,
  formatDateTime,
  formatDuration,
} from "../lib/format";
import type { AntiShield } from "../lib/useAntiShield";
import type { Screen } from "../components/Sidebar";

export function Results({ app, onNavigate }: { app: AntiShield; onNavigate: (s: Screen) => void }) {
  const summary = app.summary;
  if (!summary) {
    return (
      <div className="screen">
        <h1>Výsledky</h1>
        <p className="muted">Zatím žádná dokončená kontrola.</p>
        <button type="button" className="btn-primary" onClick={() => onNavigate("scan")}>
          Vybrat soubory ke kontrole
        </button>
      </div>
    );
  }

  const tone = summary.findings.length
    ? "alert"
    : summary.outcome.type === "completed"
      ? "good"
      : "caution";

  return (
    <div className="screen">
      <h1>Výsledky</h1>
      <section className={`result-banner tone-${tone}`}>
        <p className="big-line">
          {describeOutcome(summary.outcome)}:{" "}
          {summary.findings.length
            ? formatCount(summary.findings.length, "nález", "nálezy", "nálezů")
            : "bez nálezu"}
        </p>
        <p className="muted">
          {formatDateTime(summary.finishedAtMs)}, trvala {formatDuration(summary.finishedAtMs - summary.startedAtMs)}.{" "}
          {formatCount(summary.filesScanned, "soubor", "soubory", "souborů")}, {formatBytes(summary.bytesScanned)}.
        </p>
        <p className="muted">{summary.roots.join(", ")}</p>
      </section>

      {summary.findings.length ? (
        <section aria-labelledby="findings-title">
          <h2 id="findings-title">Nálezy</h2>
          <ul className="findings">
            {summary.findings.map((f, i) => {
              const note = findingNote(f);
              return (
                <li key={`${f.path}-${f.ruleId}-${i}`} className={`finding${f.testOnly ? " is-test" : ""}`}>
                  <p className="finding-rule">
                    {f.ruleName} <span className="muted">{f.ruleId}, verze {f.ruleVersion}</span>
                  </p>
                  <p className="finding-path">{f.path}</p>
                  <p>
                    <strong>Proč: </strong>
                    {f.evidence.map((e) => describeEvidence(e, f.ruleId)).join(" ")}
                  </p>
                  <p className="muted">{f.ruleDescription}</p>
                  {note ? <p className="finding-note">{note}</p> : null}
                  <p className="hash">SHA-256 {f.sha256}</p>
                </li>
              );
            })}
          </ul>
          <p className="muted">
            Verze 0.1 soubory jen hlásí. Karanténa a mazání přijdou v další verzi.
          </p>
        </section>
      ) : null}

      {summary.skippedTotal ? (
        <section className="panel" aria-labelledby="skipped-title">
          <h2 id="skipped-title">
            Nezkontrolováno: {formatCount(summary.skippedTotal, "položka", "položky", "položek")}
          </h2>
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
                  <span>{s.path}</span> <span className="muted">{SKIP_LABELS[s.reason.type]}</span>
                </li>
              ))}
            </ul>
          </details>
        </section>
      ) : null}

      {summary.archivesNotInspected ? (
        <p className="notice">
          {formatCount(summary.archivesNotInspected, "archiv byl zkontrolován", "archivy byly zkontrolovány", "archivů bylo zkontrolováno")}{" "}
          jen jako celek. Jejich obsah verze 0.1 nerozbaluje.
        </p>
      ) : null}

      <p className="notice">
        Kontrola porovnává soubory se sadou pravidel {summary.rulePack.version}
        {summary.rulePack.testPack ? ", která obsahuje jen testovací pravidla" : ""}. Nejde o úplnou
        antivirovou ochranu.
      </p>
    </div>
  );
}
