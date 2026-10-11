import { useState } from "react";
import { Icon } from "../components/Icon";
import { displayPath, formatBytes, formatDateTime } from "../lib/format";
import { storyFor } from "../lib/story";
import type { AntiShield } from "../lib/useAntiShield";

export function Quarantine({ app }: { app: AntiShield }) {
  const [confirming, setConfirming] = useState<string | null>(null);
  const items = app.quarantine;

  return (
    <div className="screen">
      <h1>Karanténa</h1>
      <p className="lede">
        Soubory v karanténě jsou přesunuté mimo původní místo a znehodnocené, takže je nejde spustit.
        Obnovit je jde na původní místo, nebo je trvale smazat.
      </p>
      {items.length ? (
        <ul className="quarantine-list">
          {items.map((item) => (
            <li key={item.id} className={`q-item${item.testOnly ? " is-test" : ""}`}>
              <span className="icon-tile">
                <Icon name="box" />
              </span>
              <span className="q-main">
                <strong>{item.ruleName}</strong>
                <span className="q-path" title={displayPath(item.originalPath)}>
                  {displayPath(item.originalPath)}
                </span>
                <span className="muted">
                  {formatDateTime(item.quarantinedAtMs)}, {formatBytes(item.size)}
                  {item.testOnly ? ", testovací soubor" : ""}
                </span>
              </span>
              <span className="q-actions">
                {(() => {
                  const story = storyFor(app.stories, item.originalPath, item.sha256);
                  return story ? (
                    <button type="button" className="btn-secondary small" onClick={() => app.openStory(story.id)}>
                      Příběh útoku
                    </button>
                  ) : null;
                })()}
                <button type="button" className="btn-secondary small" onClick={() => void app.restore(item.id)}>
                  <Icon name="restore" size={16} /> Obnovit
                </button>
                {confirming === item.id ? (
                  <button
                    type="button"
                    className="btn-danger small"
                    onClick={() => {
                      setConfirming(null);
                      void app.deleteQuarantined(item.id);
                    }}
                  >
                    Opravdu smazat
                  </button>
                ) : (
                  <button type="button" className="btn-link" onClick={() => setConfirming(item.id)}>
                    <Icon name="trash" size={16} /> Smazat
                  </button>
                )}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <section className="empty">
          <Icon name="check" size={32} />
          <p>Karanténa je prázdná.</p>
        </section>
      )}
    </div>
  );
}
