import { Icon } from "../components/Icon";
import { Toggle } from "../components/Toggle";
import { WEEKDAYS, relativeTime, translateReason } from "../lib/format";
import type { PresetScan, Schedule } from "../lib/types";
import type { AntiShield } from "../lib/useAntiShield";
import type { Updater } from "../lib/useUpdater";

const SCHEDULES: { value: Schedule; label: string }[] = [
  { value: "off", label: "Vypnuto" },
  { value: "daily", label: "Denně" },
  { value: "weekly", label: "Týdně" },
];

export function Settings({ app, updater }: { app: AntiShield; updater: Updater }) {
  const { settings, runtime } = app;
  if (!settings) {
    return <p className="muted">Načítám nastavení…</p>;
  }
  const save = app.saveSettings;
  const rules = runtime?.rules;

  return (
    <div className="screen settings">
      <h1>Nastavení</h1>

      <section className="panel" aria-labelledby="s-protection">
        <h2 id="s-protection">Ochrana</h2>
        <div className="toggle-list">
          <Toggle
            label="Ochrana v reálném čase"
            detail="Hlídá vybrané složky a kontroluje nové a změněné soubory."
            checked={settings.protectionEnabled}
            onChange={(v) => void save({ protectionEnabled: v })}
          />
          <Toggle
            label="Automaticky izolovat hrozby"
            detail="Nález z hlídání se hned přesune do karantény."
            checked={settings.autoQuarantine}
            onChange={(v) => void save({ autoQuarantine: v })}
          />
          <Toggle
            label="Oznámení"
            detail="Systémové oznámení při zachycení hrozby a po kontrole s nálezem."
            checked={settings.notifications}
            onChange={(v) => void save({ notifications: v })}
          />
        </div>
        <h3>Hlídané složky</h3>
        <ul className="path-list editable">
          {settings.watchFolders.map((folder) => (
            <li key={folder}>
              <Icon name="folder" size={18} />
              <span>{folder}</span>
              <button
                type="button"
                className="btn-link"
                onClick={() => void save({ watchFolders: settings.watchFolders.filter((f) => f !== folder) })}
              >
                Odebrat
              </button>
            </li>
          ))}
        </ul>
        <div className="actions">
          <button type="button" className="btn-secondary" onClick={() => void app.addWatchFolder()}>
            Přidat složku
          </button>
        </div>
      </section>

      <section className="panel" aria-labelledby="s-schedule">
        <h2 id="s-schedule">Plánovaná kontrola</h2>
        <div className="segmented" role="radiogroup" aria-label="Plánovaná kontrola">
          {SCHEDULES.map((option) => (
            <button
              key={option.value}
              type="button"
              role="radio"
              aria-checked={settings.schedule === option.value}
              className={settings.schedule === option.value ? "is-on" : undefined}
              onClick={() => void save({ schedule: option.value })}
            >
              {option.label}
            </button>
          ))}
        </div>
        {settings.schedule !== "off" ? (
          <div className="form-row">
            {settings.schedule === "weekly" ? (
              <label>
                Den
                <select
                  value={settings.scheduleWeekday}
                  onChange={(e) => void save({ scheduleWeekday: Number(e.target.value) })}
                >
                  {WEEKDAYS.map((day, i) => (
                    <option key={day} value={i + 1}>
                      {day}
                    </option>
                  ))}
                </select>
              </label>
            ) : null}
            <label>
              Hodina
              <select value={settings.scheduleHour} onChange={(e) => void save({ scheduleHour: Number(e.target.value) })}>
                {Array.from({ length: 24 }, (_, h) => (
                  <option key={h} value={h}>
                    {String(h).padStart(2, "0")}:00
                  </option>
                ))}
              </select>
            </label>
            <label>
              Druh
              <select
                value={settings.scheduleScan}
                onChange={(e) => void save({ scheduleScan: e.target.value as PresetScan })}
              >
                <option value="quick">Rychlá kontrola</option>
                <option value="full">Úplná kontrola</option>
              </select>
            </label>
          </div>
        ) : null}
        <p className="muted">
          Kontrola proběhne, jen když aplikace běží (třeba v liště). Zmeškanou kontrolu doběhne po spuštění.
          {runtime?.lastScheduledRunMs ? ` Naposledy ${relativeTime(runtime.lastScheduledRunMs)}.` : ""}
        </p>
      </section>

      <section className="panel" aria-labelledby="s-updates">
        <h2 id="s-updates">Aktualizace</h2>
        <div className="toggle-list">
          <Toggle
            label="Automaticky aktualizovat pravidla"
            detail="Každých 6 hodin stáhne podepsanou sadu pravidel a ověří ji."
            checked={settings.rulesAutoUpdate}
            onChange={(v) => void save({ rulesAutoUpdate: v })}
          />
        </div>
        <p className="muted">
          {rules?.lastSuccessMs
            ? `Pravidla naposledy ověřena ${relativeTime(rules.lastSuccessMs)}.`
            : "Pravidla se zatím neaktualizovala."}
          {rules?.lastError ? ` Poslední pokus: ${translateReason(rules.lastError)}.` : ""}
        </p>
        <div className="actions">
          <button type="button" className="btn-secondary" disabled={app.rulesBusy} onClick={() => void app.updateRules()}>
            {app.rulesBusy ? "Aktualizuji pravidla…" : "Aktualizovat pravidla teď"}
          </button>
          <button
            type="button"
            className="btn-secondary"
            disabled={updater.status === "checking" || updater.status === "installing"}
            onClick={() => void updater.check()}
          >
            Zkontrolovat novou verzi aplikace
          </button>
        </div>
      </section>

      <section className="panel" aria-labelledby="s-startup">
        <h2 id="s-startup">Spouštění</h2>
        <div className="toggle-list">
          <Toggle
            label="Spustit po přihlášení"
            detail="Ochrana naběhne sama po startu počítače (skrytá v liště)."
            checked={settings.launchAtLogin}
            onChange={(v) => void save({ launchAtLogin: v })}
          />
          <Toggle
            label="Po zavření okna běžet dál"
            detail="Okno se skryje do lišty a ochrana pokračuje. Úplně ukončit jde z ikony v liště."
            checked={settings.keepRunningInBackground}
            onChange={(v) => void save({ keepRunningInBackground: v })}
          />
        </div>
      </section>

      <section className="panel" aria-labelledby="s-look">
        <h2 id="s-look">Zvuk a animace</h2>
        <div className="toggle-list">
          <Toggle
            label="Zvuky"
            detail="Znělka při spuštění a zvuky po kontrole, nálezu a vyčištění."
            checked={settings.sounds}
            onChange={(v) => void save({ sounds: v })}
          />
          <Toggle
            label="Úvodní animace"
            detail="Animované jádro a logo při spuštění aplikace."
            checked={settings.intro}
            onChange={(v) => void save({ intro: v })}
          />
          <Toggle
            label="Omezit pohyb"
            detail="Vypne nekonečné animace (šetří baterii a výkon)."
            checked={settings.reducedMotion}
            onChange={(v) => void save({ reducedMotion: v })}
          />
        </div>
      </section>
    </div>
  );
}
