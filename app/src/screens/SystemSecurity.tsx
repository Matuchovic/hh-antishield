import { useEffect, useState } from "react";
import { Icon } from "../components/Icon";
import { api } from "../lib/api";
import { capitalize, formatCount, translateReason } from "../lib/format";
import type { PostureState, PrivacyGrant, PrivacyReport } from "../lib/types";
import type { AntiShield } from "../lib/useAntiShield";

const STATE_TEXT: Record<PostureState, string> = {
  ok: "Zapnuto",
  warning: "Vypnuto",
  unknown: "Nelze zjistit",
};

/** Ochrany, ke kterým jde otevřít příslušný panel Nastavení systému. */
const SETTINGS_PAGES: Record<string, string[]> = {
  macos: ["gatekeeper", "filevault", "firewall", "xprotect"],
  windows: ["defender", "firewall"],
};

/** Oprávnění v pořadí podle rizika; spyware zneužívá hlavně první čtyři. */
const PRIVACY_SERVICES: { service: PrivacyGrant["service"]; title: string; risk: string }[] = [
  { service: "screen", title: "Nahrávání obrazovky", risk: "vidí vše, co je na obrazovce" },
  { service: "accessibility", title: "Zpřístupnění", risk: "může ovládat počítač a číst okna" },
  { service: "input", title: "Sledování vstupu", risk: "vidí, co píšete na klávesnici" },
  { service: "fullDisk", title: "Plný přístup k disku", risk: "čte všechny soubory včetně pošty" },
  { service: "camera", title: "Kamera", risk: "" },
  { service: "microphone", title: "Mikrofon", risk: "" },
];

/** Soukromí: kdo má přístup ke kameře, mikrofonu, obrazovce a klávesnici. */
function PrivacyPanel() {
  const [report, setReport] = useState<PrivacyReport | null>(null);
  useEffect(() => {
    void api
      .privacyReport()
      .then(setReport)
      .catch(() => setReport({ fullDiskAccess: null, grants: [], problem: "not available on this system" }));
  }, []);
  if (!report || report.fullDiskAccess === null) {
    return null;
  }
  const open = (id: string) => void api.openSystemSettings(id).catch(() => undefined);
  return (
    <section className="panel" aria-labelledby="privacy-title">
      <h2 id="privacy-title">Soukromí: oprávnění aplikací</h2>
      {!report.fullDiskAccess ? (
        <>
          <p className="notice">
            Pro přehled oprávnění a kontrolu příloh v Apple Mail potřebuje AntiShield plný přístup k disku. macOS
            ho jinak nedovolí číst. AntiShield nic nemění, jen čte a upozorní.
          </p>
          <div className="actions">
            <button type="button" className="btn-secondary" onClick={() => open("fullDisk")}>
              Povolit plný přístup k disku
            </button>
          </div>
        </>
      ) : report.problem ? (
        <p className="notice tone-alert">{capitalize(translateReason(report.problem))}.</p>
      ) : (
        <>
          <p className="muted">
            Pokud aplikaci v seznamu nepoznáváte, odeberte jí oprávnění. Když nová aplikace získá některé
            z prvních čtyř oprávnění, AntiShield upozorní.
          </p>
          <ul className="privacy-list">
            {PRIVACY_SERVICES.map(({ service, title, risk }) => {
              const clients = report.grants.filter((g) => g.service === service).map((g) => g.client);
              return (
                <li key={service} className="privacy-group">
                  <div className="privacy-head">
                    <strong>{title}</strong>
                    <span className="muted">
                      {clients.length
                        ? formatCount(clients.length, "aplikace", "aplikace", "aplikací")
                        : "žádná aplikace"}
                    </span>
                    <button type="button" className="btn-link" onClick={() => open(service)}>
                      Upravit v Nastavení
                    </button>
                  </div>
                  {risk ? <p className="muted">Aplikace s tímto oprávněním {risk}.</p> : null}
                  {clients.length ? <p className="privacy-clients">{clients.join(", ")}</p> : null}
                </li>
              );
            })}
          </ul>
        </>
      )}
    </section>
  );
}

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
  const os = app.info?.platform.split("-")[0] ?? "";
  const pages = SETTINGS_PAGES[os] ?? [];

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
                  {check.state !== "ok" && pages.includes(check.id) ? (
                    <button
                      type="button"
                      className="btn-link"
                      onClick={() => void api.openSystemSettings(check.id).catch(() => undefined)}
                    >
                      {os === "macos" ? "Otevřít Nastavení systému" : "Otevřít Zabezpečení Windows"}
                    </button>
                  ) : null}
                </span>
                <span className="posture-state">{STATE_TEXT[check.state]}</span>
              </li>
            ))}
          </ul>
        </>
      )}
      <PrivacyPanel />
    </div>
  );
}
