import { type KeyboardEvent, useEffect, useRef } from "react";
import { SEVERITY_LABELS, type StepIcon, stepTime, storyAdvice, storySteps, storySummary, targetOf } from "../lib/story";
import type { AntiShield } from "../lib/useAntiShield";
import { Icon, type IconName } from "./Icon";
import type { Screen } from "./Sidebar";

const ICONS: Record<StepIcon, IconName> = {
  globe: "globe",
  mail: "mail",
  drive: "drive",
  folder: "folder",
  play: "play",
  power: "power",
  shield: "shield",
  box: "box",
  alert: "warning",
};

/** Příběh útoku: od příchodu hrozby po zásah, jako časová osa. */
export function StorySheet({ app, onNavigate }: { app: AntiShield; onNavigate: (s: Screen) => void }) {
  const { story, closeStory } = app;
  const sheet = useRef<HTMLElement>(null);

  useEffect(() => {
    if (story) sheet.current?.querySelector<HTMLElement>("button")?.focus();
  }, [story?.id]);

  if (!story) return null;
  const steps = storySteps(story);
  const advice = storyAdvice(story);
  const pending = story.outcome.type !== "quarantined";
  const cleaning = app.cleaning[story.finding.path];
  const tone = story.finding.testOnly ? "caution" : "alert";

  // Klávesnice zůstává v dialogu; Esc ho zavře.
  const onKeyDown = (e: KeyboardEvent<HTMLElement>) => {
    if (e.key === "Escape") {
      e.preventDefault();
      closeStory();
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
    <div className="story-backdrop" onClick={(e) => e.target === e.currentTarget && closeStory()}>
      <section
        ref={sheet}
        className={`story-sheet tone-${tone}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby="story-title"
        aria-describedby="story-summary"
        onKeyDown={onKeyDown}
      >
        <header className="story-head">
          <span className="story-badge">
            <Icon name="warning" size={16} /> Příběh útoku
          </span>
          <button type="button" className="story-close" onClick={closeStory} aria-label="Zavřít příběh">
            <Icon name="close" size={18} />
          </button>
          <h2 id="story-title">{targetOf(story.finding.path).name}</h2>
          <p className="story-rule">
            {story.finding.ruleName} <span className={`sev sev-${story.finding.severity}`}>{SEVERITY_LABELS[story.finding.severity]}</span>
          </p>
          <p id="story-summary" className="story-summary">
            {storySummary(story)}
          </p>
        </header>

        <ol className="story-timeline">
          {steps.map((step, i) => (
            <li key={step.id} className={`story-step tone-${step.tone}`} style={{ animationDelay: `${0.15 + i * 0.12}s` }}>
              <span className="story-dot" aria-hidden="true">
                <Icon name={ICONS[step.icon]} size={16} />
              </span>
              <div className="story-body">
                <div className="story-line">
                  <strong>{step.title}</strong>
                  {step.atMs !== null ? <time className="muted">{stepTime(step.atMs)}</time> : null}
                </div>
                {step.lines.map((line) => (
                  <p key={line} className="muted">
                    {line}
                  </p>
                ))}
              </div>
            </li>
          ))}
        </ol>

        <div className="story-advice">
          <h3>Co dál</h3>
          <ul>
            {advice.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>

        <footer className="story-foot">
          <code title="SHA-256">{story.finding.sha256.slice(0, 16)}…</code>
          <div className="actions">
            {pending ? (
              <button
                type="button"
                className="btn-danger"
                disabled={cleaning === "busy"}
                onClick={() => void app.remediate([story.finding.path])}
              >
                {cleaning === "busy" ? "Čistím…" : "Vyčistit"}
              </button>
            ) : (
              <button
                type="button"
                className="btn-secondary"
                onClick={() => {
                  closeStory();
                  onNavigate("quarantine");
                }}
              >
                Otevřít Karanténu
              </button>
            )}
            <button type="button" className="btn-link" onClick={closeStory}>
              Zavřít
            </button>
          </div>
        </footer>
      </section>
    </div>
  );
}
