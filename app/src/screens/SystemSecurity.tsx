import { useEffect } from "react";
import { Icon } from "../components/Icon";
import type { PostureState } from "../lib/types";
import type { AntiShield } from "../lib/useAntiShield";

const STATE_TEXT: Record<PostureState, string> = {
  ok: "Zapnuto",
  warning: "Vypnuto",
  unknown: "Nelze zjistit",
};

const STATE_TONE: Record<PostureState, string> = {
  ok: "good",
  warning: "alert",
  unknown: "off",
};

export function SystemSecurity({ app }: { app: AntiShield }) {
  const { posture, refreshPosture } = app;
  useEffect(() => {
    if (posture === null) void refreshPosture();
    // Načíst jen při prvním otevření obrazovky.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const warnings = posture?.filter((c) => c.state === "warning").length ?? 0;

  return (
    <div className="screen">
      <div className="panel-head">
        <h1>Bezpečnost systému</h1>
        <button type="button" className="btn-secondary" onClick={() => void refreshPosture()}>
          Zkontrolovat znovu
        </button>
      </div>
      <p className="lede">
        Ochrany vestavěné v systému jsou základ. AntiShield jejich stav jen čte a poradí, jak je zapnout;
        sám v systému nic nemění.
      </p>
      {posture === null ? (
        <p className="muted">Zjišťuji stav…</p>
      ) : (
        <>
          <p className={`result-banner tone-${warnings ? "alert" : "good"}`}>
            {warnings ? `Vypnuté ochrany: ${warnings}. Doporučujeme je zapnout.` : "Všechny zjištěné ochrany systému jsou zapnuté."}
          </p>
          <ul className="posture-list">
            {posture.map((check) => (
              <li key={check.id} className={`posture tone-${STATE_TONE[check.state]}`}>
                <span className="icon-tile">
                  <Icon name={check.state === "ok" ? "check" : check.state === "warning" ? "warning" : "info"} />
                </span>
                <span className="posture-main">
                  <strong>{check.title}</strong>
                  <span className="muted">{check.detail}</span>
                  {check.advice ? <span className="posture-advice">{check.advice}</span> : null}
                </span>
                <span className="posture-state">{STATE_TEXT[check.state]}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
