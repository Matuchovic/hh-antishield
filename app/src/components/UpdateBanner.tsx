import { describeError, formatBytes } from "../lib/format";
import type { Updater } from "../lib/useUpdater";
import { Icon } from "./Icon";

/** Banner nahoře v aplikaci: nová verze, stahování, chyba instalace. */
export function UpdateBanner({ updater }: { updater: Updater }) {
  const { status, info, progress, error } = updater;
  const installError = status === "error" && info !== null;
  if (!info || updater.dismissed || !(status === "available" || status === "installing" || installError)) {
    return null;
  }
  const total = progress?.total ?? null;
  const share = total ? Math.min(1, (progress?.downloaded ?? 0) / total) : null;

  return (
    <div className={`update-banner${status === "installing" ? " is-installing" : ""}`} role="status">
      <span className="icon-tile">
        <Icon name="download" />
      </span>
      <div className="update-copy">
        <p className="update-title">
          {status === "installing" ? `Instaluji verzi ${info.version}` : `Je k dispozici verze ${info.version}`}
        </p>
        <p className="update-detail">
          {installError && error
            ? describeError(error)
            : status === "installing"
              ? progress
                ? `Staženo ${formatBytes(progress.downloaded)}${total ? ` z ${formatBytes(total)}` : ""}. Podpis se ověří před instalací, pak se aplikace restartuje.`
                : "Připravuji stahování…"
              : (info.notes ?? `Máte verzi ${info.currentVersion}.`)}
        </p>
        {status === "installing" ? (
          <div className="update-track">
            <span
              className={share === null ? "is-indeterminate" : undefined}
              ref={(el) => el?.style.setProperty("--fill", String(share ?? 0.3))}
            />
          </div>
        ) : null}
      </div>
      {status !== "installing" ? (
        <div className="update-actions">
          <button type="button" className="btn-primary" onClick={() => void updater.install()}>
            {installError ? "Zkusit znovu" : "Aktualizovat"}
          </button>
          <button type="button" className="btn-link" onClick={updater.dismiss}>
            Později
          </button>
        </div>
      ) : null}
    </div>
  );
}
