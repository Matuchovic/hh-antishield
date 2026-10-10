import { useState } from "react";
import { Sidebar, type Screen } from "./components/Sidebar";
import { describeError } from "./lib/format";
import { useAntiShield } from "./lib/useAntiShield";
import { About } from "./screens/About";
import { Events } from "./screens/Events";
import { Overview } from "./screens/Overview";
import { Planned } from "./screens/Planned";
import { Results } from "./screens/Results";
import { Scan } from "./screens/Scan";

export function App() {
  const app = useAntiShield();
  const [screen, setScreen] = useState<Screen>("overview");

  const content = (() => {
    switch (screen) {
      case "overview":
        return <Overview app={app} onNavigate={setScreen} />;
      case "scan":
        return <Scan app={app} onNavigate={setScreen} />;
      case "results":
        return <Results app={app} onNavigate={setScreen} />;
      case "events":
        return <Events app={app} />;
      case "about":
        return <About app={app} />;
      case "realtime":
      case "quarantine":
      case "systemcare":
        return <Planned feature={screen} />;
    }
  })();

  return (
    <div className="app">
      <Sidebar screen={screen} onNavigate={setScreen} info={app.info} scanRunning={app.scan.running} />
      <main className="content">
        {app.error ? (
          <div className="error-bar" role="alert">
            <span>{describeError(app.error)}</span>
            <button type="button" className="btn-link" onClick={app.dismissError}>
              Zavřít
            </button>
          </div>
        ) : null}
        {content}
      </main>
    </div>
  );
}
