import { useEffect, useState } from "react";
import { AccessPrompt } from "./components/AccessPrompt";
import { FleetApprovals } from "./components/FleetMember";
import { Intro } from "./components/Intro";
import { Sidebar, type Screen } from "./components/Sidebar";
import { StorySheet } from "./components/StorySheet";
import { UpdateBanner } from "./components/UpdateBanner";
import { onAppEvent } from "./lib/api";
import { describeError } from "./lib/format";
import { useAntiShield } from "./lib/useAntiShield";
import { useFleet } from "./lib/useFleet";
import { useUpdater } from "./lib/useUpdater";
import { About } from "./screens/About";
import { Care } from "./screens/Care";
import { Events } from "./screens/Events";
import { Fleet } from "./screens/Fleet";
import { Overview } from "./screens/Overview";
import { Protection } from "./screens/Protection";
import { Quarantine } from "./screens/Quarantine";
import { Results } from "./screens/Results";
import { Scan } from "./screens/Scan";
import { Settings } from "./screens/Settings";
import { SystemSecurity } from "./screens/SystemSecurity";

const SCREENS: Screen[] = [
  "overview",
  "scan",
  "results",
  "events",
  "realtime",
  "quarantine",
  "systemcare",
  "care",
  "fleet",
  "settings",
  "about",
];

function prefersReducedMotion(): boolean {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

export function App() {
  const app = useAntiShield();
  const updater = useUpdater();
  const fleet = useFleet();
  const [screen, setScreen] = useState<Screen>("overview");
  const [intro, setIntro] = useState<"pending" | "show" | "done">("pending");
  const settings = app.settings;

  // Znělka jen jednou po spuštění, a jen když ji uživatel nevypnul.
  useEffect(() => {
    if (intro !== "pending" || !settings) return;
    setIntro(settings.intro && !settings.reducedMotion && !prefersReducedMotion() ? "show" : "done");
  }, [intro, settings]);

  // Omezení pohybu z nastavení a pozastavení animací, když okno není vidět.
  useEffect(() => {
    document.documentElement.classList.toggle("reduce-motion", Boolean(settings?.reducedMotion));
  }, [settings?.reducedMotion]);
  useEffect(() => {
    const sync = () => document.documentElement.classList.toggle("is-hidden", document.hidden);
    sync();
    document.addEventListener("visibilitychange", sync);
    return () => document.removeEventListener("visibilitychange", sync);
  }, []);

  // Lišta může poslat okno na konkrétní obrazovku (např. rychlá kontrola).
  useEffect(() => {
    const stop = onAppEvent<string>("navigate", (target) => {
      if ((SCREENS as string[]).includes(target)) setScreen(target as Screen);
    });
    return () => void stop.then((fn) => fn());
  }, []);

  // Reflektor pod kurzorem na panelech (jen CSS proměnné, žádný stav).
  useEffect(() => {
    let frame = 0;
    const onMove = (e: PointerEvent) => {
      if (frame) return;
      frame = requestAnimationFrame(() => {
        frame = 0;
        const el = (e.target as Element | null)?.closest?.(".panel, .tile, .preset");
        if (!(el instanceof HTMLElement)) return;
        const r = el.getBoundingClientRect();
        el.style.setProperty("--mx", `${e.clientX - r.left}px`);
        el.style.setProperty("--my", `${e.clientY - r.top}px`);
      });
    };
    document.addEventListener("pointermove", onMove, { passive: true });
    return () => {
      document.removeEventListener("pointermove", onMove);
      cancelAnimationFrame(frame);
    };
  }, []);

  const content = (() => {
    switch (screen) {
      case "overview":
        return <Overview app={app} onNavigate={setScreen} />;
      case "scan":
        return <Scan app={app} onNavigate={setScreen} />;
      case "results":
        return <Results app={app} onNavigate={setScreen} />;
      case "realtime":
        return <Protection app={app} onNavigate={setScreen} />;
      case "quarantine":
        return <Quarantine app={app} />;
      case "systemcare":
        return <SystemSecurity app={app} />;
      case "care":
        return <Care app={app} />;
      case "fleet":
        return fleet.admin ? (
          <Fleet
            fleet={fleet.admin}
            onUpdate={fleet.setAdmin}
            still={Boolean(settings?.reducedMotion) || prefersReducedMotion()}
          />
        ) : (
          <Overview app={app} onNavigate={setScreen} />
        );
      case "events":
        return <Events app={app} />;
      case "settings":
        return <Settings app={app} updater={updater} fleet={fleet} onOpenFleet={() => setScreen("fleet")} />;
      case "about":
        return <About app={app} updater={updater} />;
    }
  })();

  return (
    <div className={`app${intro === "show" ? " behind-intro" : ""}`}>
      <Sidebar
        screen={screen}
        onNavigate={setScreen}
        info={app.info}
        level={app.protection?.level ?? null}
        scanRunning={app.scan.running}
        quarantineCount={app.quarantine.length}
        fleetAdmin={Boolean(fleet.admin)}
        managedBy={fleet.member?.fleetName ?? null}
      />
      {app.scan.running ? <div className="scan-line" aria-hidden="true" /> : null}
      <main className="content">
        <UpdateBanner updater={updater} />
        <FleetApprovals fleet={fleet} />
        {app.error ? (
          <div className="error-bar" role="alert">
            <span>{describeError(app.error)}</span>
            <button type="button" className="btn-link" onClick={app.dismissError}>
              Zavřít
            </button>
          </div>
        ) : null}
        <div key={screen} className="view">
          {content}
        </div>
      </main>
      <AccessPrompt app={app} paused={intro !== "done"} />
      <StorySheet app={app} onNavigate={setScreen} />
      {intro === "show" ? <Intro sound={settings?.sounds ?? true} onDone={() => setIntro("done")} /> : null}
    </div>
  );
}
