import { type KeyboardEvent, useCallback, useEffect, useState } from "react";
import brandLogo from "../assets/hh-antishield-logo.png";
import { api } from "../lib/api";
import type { AntiShield } from "../lib/useAntiShield";
import { Icon } from "./Icon";

/** Jak často se při čekání na povolení ověřuje přístup. */
const WAIT_POLL_MS = 2000;

type Phase = "ask" | "waiting" | "restart" | "granted";

/**
 * Žádost o plný přístup k disku (macOS). Systém o něj sám nepožádá a aplikace
 * si ho zapnout nesmí, proto se žádost ukáže po spuštění, dokud přístup chybí.
 * Tlačítko otevře správný panel Nastavení systému a povolení se pozná samo.
 */
export function AccessPrompt({ app, paused }: { app: AntiShield; paused: boolean }) {
  const access = app.runtime?.fullDiskAccess ?? null;
  const { refreshStatus } = app;
  const [phase, setPhase] = useState<Phase>("ask");
  const [closed, setClosed] = useState(false);
  const [shown, setShown] = useState(false);
  const [restarting, setRestarting] = useState(false);

  const asking = access === false && !closed && !paused;
  useEffect(() => {
    if (asking) setShown(true);
  }, [asking]);

  // Přístup povolený, zatímco žádost byla vidět: potvrdit.
  useEffect(() => {
    if (access === true && shown && !closed) setPhase("granted");
  }, [access, shown, closed]);

  // Při čekání ověřovat častěji; po návratu z Nastavení systému, když přístup
  // pořád chybí, nabídnout restart (macOS ho často předá až novému procesu).
  const waiting = phase === "waiting" || phase === "restart";
  useEffect(() => {
    if (!waiting) return;
    const timer = window.setInterval(() => void refreshStatus(), WAIT_POLL_MS);
    const onReturn = () => {
      void refreshStatus().then(() => setPhase((p) => (p === "waiting" ? "restart" : p)));
    };
    window.addEventListener("focus", onReturn);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener("focus", onReturn);
    };
  }, [waiting, refreshStatus]);

  const close = useCallback(() => setClosed(true), []);
  const openSettings = useCallback(() => {
    setPhase((p) => (p === "ask" ? "waiting" : p));
    void api.openSystemSettings("fullDisk").catch(() => undefined);
  }, []);
  const restart = useCallback(() => {
    setRestarting(true);
    void api.restartApp().catch(() => setRestarting(false));
  }, []);

  const visible = !paused && !closed && (asking || (phase === "granted" && shown));
  if (!visible) return null;

  // Klávesnice zůstává v dialogu; Esc ho zavře.
  const onKeyDown = (e: KeyboardEvent<HTMLElement>) => {
    if (e.key === "Escape") {
      e.preventDefault();
      close();
      return;
    }
    if (e.key !== "Tab") return;
    const items = Array.from(e.currentTarget.querySelectorAll<HTMLElement>("button:not(:disabled)"));
    const first = items[0];
    const last = items[items.length - 1];
    if (!first || !last) return;
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  };

  return (
    <div className="access-backdrop">
      <section
        className="access-sheet"
        role="dialog"
        aria-modal="true"
        aria-labelledby="access-title"
        aria-describedby="access-lede"
        onKeyDown={onKeyDown}
      >
        {phase === "granted" ? (
          <>
            <span className="access-done" aria-hidden="true">
              <Icon name="check" size={26} />
            </span>
            <h2 id="access-title">Plný přístup je povolený</h2>
            <p id="access-lede" className="access-lede">
              AntiShield teď smí kontrolovat i přílohy v Apple Mail a hlídat, které aplikace získají citlivá
              oprávnění. Stav obou ochran uvidíte v přehledu.
            </p>
            <div className="actions">
              <button type="button" className="btn-primary" onClick={close} autoFocus>
                Hotovo
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="access-row" aria-hidden="true">
              <img src={brandLogo} alt="" />
              <strong>H&amp;H AntiShield</strong>
              <span className="access-switch" />
            </div>
            <h2 id="access-title">Povolte AntiShieldu plný přístup k disku</h2>
            <p id="access-lede" className="access-lede">
              Bez něj macOS AntiShieldu nedovolí zkontrolovat přílohy v Apple Mail ani zjistit, které aplikace smí
              nahrávat obrazovku nebo číst celý disk. Povolit ho můžete jen vy, aplikace si ho zapnout nesmí.
            </p>
            <ol className="access-steps">
              <li>Otevřete Nastavení systému na panelu Plný přístup k disku.</li>
              <li>Zapněte H&amp;H AntiShield. Když v seznamu chybí, přidejte ho tlačítkem + ze složky Aplikace.</li>
              <li>Když macOS nabídne AntiShield ukončit a znovu otevřít, potvrďte to.</li>
            </ol>
            {phase === "restart" ? (
              <p className="notice">
                Přepínač u AntiShieldu je zapnutý a přístup pořád chybí? macOS ho předá až po restartu AntiShieldu.
                Po aktualizaci AntiShieldu bývá potřeba přepínač vypnout a znovu zapnout.
              </p>
            ) : phase === "waiting" ? (
              <p className="access-wait" role="status">
                <span className="access-spinner" aria-hidden="true" />
                Čekám, až přístup povolíte…
              </p>
            ) : null}
            <div className="actions">
              {phase === "restart" ? (
                <>
                  <button type="button" className="btn-primary" onClick={restart} disabled={restarting} autoFocus>
                    {restarting ? "Restartuji AntiShield…" : "Restartovat AntiShield"}
                  </button>
                  <button type="button" className="btn-secondary" onClick={openSettings}>
                    Otevřít Nastavení systému
                  </button>
                </>
              ) : (
                <button type="button" className="btn-primary" onClick={openSettings} autoFocus>
                  Otevřít Nastavení systému
                </button>
              )}
              <button type="button" className="btn-link" onClick={close}>
                Teď ne
              </button>
            </div>
          </>
        )}
      </section>
    </div>
  );
}
