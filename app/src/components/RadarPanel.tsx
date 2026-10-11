import { formatCount, formatDateTime, formatTime } from "../lib/format";
import type { ActivityLog, RecentCheck } from "../lib/types";
import type { AntiShield } from "../lib/useAntiShield";
import { Core } from "./Emblem";
import { RadarCanvas } from "./Radar";

const KIND_LABELS: Record<RecentCheck["kind"], string> = {
  download: "Stažený soubor",
  file: "Soubor",
  mail: "Příloha e-mailu",
  program: "Spuštěný program",
  startup: "Položka po přihlášení",
  scan: "Kontrola",
};

const COUNTS: { key: keyof Omit<ActivityLog, "sinceMs" | "recent">; label: [string, string, string] }[] = [
  { key: "downloads", label: ["stažený soubor", "stažené soubory", "stažených souborů"] },
  { key: "files", label: ["soubor", "soubory", "souborů"] },
  { key: "mail", label: ["příloha", "přílohy", "příloh"] },
  { key: "programs", label: ["program", "programy", "programů"] },
  { key: "startup", label: ["položka po přihlášení", "položky po přihlášení", "položek po přihlášení"] },
];

/** Stabilní klíč položky (nové položky naskočí, staré se nepřekreslují). */
function feedKey(all: RecentCheck[], index: number): string {
  const key = (item: RecentCheck) => `${item.atMs}-${item.kind}-${item.name}`;
  const base = key(all[index] as RecentCheck);
  const earlier = all.slice(0, index).filter((item) => key(item) === base).length;
  return earlier ? `${base}-${earlier}` : base;
}

/** Radar ochrany: živý přehled toho, co hlídání právě kontroluje. */
export function RadarPanel({ app }: { app: AntiShield }) {
  const log = app.runtime?.activity;
  const still =
    Boolean(app.settings?.reducedMotion) || window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const recent = log?.recent.slice(0, 8) ?? [];
  const total = log ? log.downloads + log.files + log.mail + log.programs + log.startup : 0;

  return (
    <section className="panel radar-panel" aria-labelledby="radar-title">
      <div className="panel-head">
        <h2 id="radar-title">Radar ochrany</h2>
        <span className="muted">
          {log?.sinceMs ? `od ${formatDateTime(log.sinceMs)}` : "čeká na první kontrolu"}
        </span>
      </div>
      <div className="radar-grid">
        <div className="radar-scope" aria-hidden="true">
          <RadarCanvas className="radar-canvas" scanning={app.scan.running} still={still} rings coreRatio={0.17} />
          <div className="radar-core">
            <Core />
          </div>
        </div>
        <div className="radar-side">
          <p className="radar-total">
            <strong>{total.toLocaleString("cs-CZ")}</strong> zkontrolovaných položek
            {log?.threats ? (
              <span className="radar-threats"> a {formatCount(log.threats, "hrozba", "hrozby", "hrozeb")}</span>
            ) : null}
          </p>
          <ul className="radar-counts">
            {COUNTS.filter(({ key }) => (log?.[key] ?? 0) > 0).map(({ key, label }) => (
              <li key={key}>{formatCount(log?.[key] ?? 0, ...label)}</li>
            ))}
          </ul>
          <h3 className="radar-feed-title">Právě zkontrolováno</h3>
          {recent.length ? (
            <ul className="radar-feed">
              {recent.map((item, i, all) => (
                <li key={feedKey(all, i)} className={item.threat ? "is-threat" : undefined}>
                  <span className="radar-name" title={item.name}>
                    {item.name}
                  </span>
                  <span className="muted">{item.threat ? "hrozba" : KIND_LABELS[item.kind]}</span>
                  <time className="muted">{formatTime(item.atMs)}</time>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">
              Zatím nic. Jakmile hlídání zkontroluje nový soubor nebo spuštěný program, objeví se tady i na radaru.
            </p>
          )}
        </div>
      </div>
      <p className="muted radar-legend">
        Každý bod je skutečně zkontrolovaná položka: na okraji stažené soubory, blíž ke středu ostatní soubory a
        přílohy, u jádra spuštěné programy. Hrozba svítí rudě.
      </p>
    </section>
  );
}
