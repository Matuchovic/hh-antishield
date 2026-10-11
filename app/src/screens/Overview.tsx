import { Backdrop } from "../components/Backdrop";
import { Emblem } from "../components/Emblem";
import { Icon, type IconName } from "../components/Icon";
import type { Screen } from "../components/Sidebar";
import { TileArt, type TileArtKind } from "../components/TileArt";
import {
  COMPONENT_LABELS,
  describeAuditEvent,
  describeOutcome,
  formatCount,
  formatDate,
  formatDateTime,
  formatTime,
  headline,
  platformName,
  stateTone,
  type Tone,
} from "../lib/format";
import type { AuditEvent, ComponentKind, ComponentState, ProtectionLevel } from "../lib/types";
import type { AntiShield } from "../lib/useAntiShield";
import { useCountUp } from "../lib/useCountUp";

const LAYERS: { kind: ComponentKind; icon: IconName; desc: string }[] = [
  { kind: "onDemandScan", icon: "search", desc: "Soubory, které vyberete" },
  { kind: "realTimeProtection", icon: "shield", desc: "Průběžné sledování" },
  { kind: "webProtection", icon: "globe", desc: "Stažené soubory" },
  { kind: "emailProtection", icon: "mail", desc: "Přílohy a odkazy" },
  { kind: "privacyProtection", icon: "lock", desc: "Osobní data" },
];

const HEALTH: { kind: ComponentKind; label: string; icon: IconName }[] = [
  { kind: "detectionEngine", label: "Engine", icon: "engine" },
  { kind: "rulePack", label: "Pravidla", icon: "key" },
  { kind: "auditLog", label: "Audit", icon: "doc" },
];

const PILL: Record<ProtectionLevel, { text: string; tone: Tone }> = {
  protected: { text: "Vše funguje správně", tone: "good" },
  manualScanOnly: { text: "Jen ruční kontrola", tone: "caution" },
  notReady: { text: "Kontrola není připravená", tone: "alert" },
};

const TILES: { n: string; title: string; text: string; art: TileArtKind; screen: Screen; planned: boolean }[] = [
  { n: "01", title: "Kontrola souborů", text: "Prověřte vybrané dokumenty, aplikace a složky.", art: "folder", screen: "scan", planned: false },
  { n: "02", title: "Ochrana v reálném čase", text: "Plánováno pro další verze.", art: "lock", screen: "realtime", planned: true },
  { n: "03", title: "System Care", text: "Plánováno pro další verze.", art: "wrench", screen: "systemcare", planned: true },
];

function layerText(kind: ComponentKind, state: ComponentState): string {
  switch (state.type) {
    case "running":
      return kind === "onDemandScan" ? "Připraveno" : "Aktivní";
    case "notImplemented":
      return "Není ve v0.1";
    case "disabled":
      return "Vypnuto";
    case "degraded":
      return "Omezeno";
    case "failed":
      return "Selhalo";
  }
}

function eventTone(event: AuditEvent): Tone {
  switch (event.kind) {
    case "finding":
    case "rule_pack_rejected":
      return "alert";
    case "audit_integrity_issue":
      return "caution";
    case "self_test":
      return event.data.passed ? "good" : "alert";
    default:
      return "good";
  }
}

function Count({ value }: { value: number }) {
  return <>{useCountUp(value).toLocaleString("cs-CZ")}</>;
}

export function Overview({ app, onNavigate }: { app: AntiShield; onNavigate: (s: Screen) => void }) {
  const { protection, summary, events, info, scan } = app;
  if (!protection) {
    return <p className="muted">Načítám stav enginu…</p>;
  }
  const h = headline(protection.level, protection.components);
  const ready = protection.level !== "notReady";
  const pill = PILL[protection.level];
  const stateOf = (kind: ComponentKind) =>
    protection.components.find((c) => c.kind === kind)?.state ?? ({ type: "notImplemented" } as ComponentState);

  const title = scan.running ? "Kontrola právě běží" : h.title;
  const words = title.split(" ");
  const accent = words.pop() ?? "";
  const detail = scan.running
    ? `Zkontrolováno ${formatCount(scan.progress?.filesScanned ?? 0, "soubor", "soubory", "souborů")}.`
    : h.detail;

  const startWith = async (kind: "folders" | "files") => {
    await app.pick(kind);
    onNavigate("scan");
  };

  const pack = info?.rulePack;
  const validity = pack
    ? Math.max(0, Math.min(1, (pack.expiresAtUnix - Date.now() / 1000) / (pack.expiresAtUnix - pack.createdAtUnix)))
    : 0;

  return (
    <div className="overview">
      <section className={`hero reveal d1 tone-${scan.running ? "good" : h.tone}`} aria-labelledby="hero-title">
        <Backdrop intense={scan.running} />
        <p className="hero-tag left">
          <strong>H&amp;H AntiShield</strong>
          <br />
          Ruční kontrola souborů
        </p>
        <p className="hero-tag right">
          <strong>Verze 0.1</strong>
          <br />
          {info ? platformName(info.platform) : ""}
        </p>
        <Emblem components={protection.components} scanning={scan.running} />
        <p className="hero-title">H&amp;H AntiShield</p>
        <h1 id="hero-title" className="hero-headline">
          {words.join(" ")} <em>{accent}</em>
        </h1>
        <p className="hero-detail">{detail}</p>
        {scan.running ? (
          <button type="button" className="cta" onClick={() => onNavigate("scan")}>
            <Icon name="search" size={22} />
            <span>Zobrazit průběh</span>
            <Icon name="chevron" size={20} className="cta-chev" />
          </button>
        ) : (
          <>
            <button type="button" className="cta" disabled={!ready} onClick={() => void startWith("folders")}>
              <Icon name="search" size={22} />
              <span>Spustit kontrolu</span>
              <Icon name="chevron" size={20} className="cta-chev" />
            </button>
            <p className="hero-alt">
              nebo{" "}
              <button type="button" className="btn-link" disabled={!ready} onClick={() => void startWith("files")}>
                vybrat jednotlivé soubory
              </button>
            </p>
          </>
        )}
      </section>

      <section className="panel status reveal d2" aria-labelledby="status-title">
        <div className="status-head">
          <span className="icon-tile">
            <Icon name="shield" />
          </span>
          <h2 id="status-title">Stav ochrany</h2>
          <span className={`status-pill tone-${pill.tone}`}>
            <span className="dot" aria-hidden="true" />
            {pill.text}
          </span>
        </div>
        <ul className="layers">
          {LAYERS.map((layer) => {
            const state = stateOf(layer.kind);
            return (
              <li key={layer.kind} className={`layer-row tone-${stateTone(state)}`}>
                <span className="icon-tile">
                  <Icon name={layer.icon} />
                </span>
                <span>
                  <span className="layer-name">{COMPONENT_LABELS[layer.kind]}</span>
                  <span className="layer-desc">{layer.desc}</span>
                </span>
                <span className="layer-state">
                  {layerText(layer.kind, state)}
                  <span className="capsule" aria-hidden="true" />
                </span>
              </li>
            );
          })}
        </ul>
        <ul className="health" aria-label="Stav enginu">
          {HEALTH.map((item) => (
            <li key={item.kind} className={`tone-${stateTone(stateOf(item.kind))}`}>
              <span className="dot" aria-hidden="true" />
              {item.label}
            </li>
          ))}
        </ul>
      </section>

      <section className="panel last reveal d3" aria-labelledby="last-title">
        <div className="card-title">
          <span className="icon-tile">
            <Icon name="calendar" />
          </span>
          <h2 id="last-title">Poslední kontrola</h2>
          {summary ? (
            <button type="button" className="card-go" aria-label="Zobrazit výsledky" onClick={() => onNavigate("results")}>
              <Icon name="chevron" />
            </button>
          ) : null}
        </div>
        {summary ? (
          <>
            <p className="big-date">{formatDateTime(summary.finishedAtMs)}</p>
            <p className={summary.findings.length ? "tone-text-alert" : "muted"}>
              {summary.findings.length
                ? `${formatCount(summary.findings.length, "nález", "nálezy", "nálezů")}, otevřete výsledky.`
                : `${describeOutcome(summary.outcome)}, žádná shoda s pravidly.`}
            </p>
            <div className="mini-stats">
              <span>
                <strong>
                  <Count value={summary.filesScanned} />
                </strong>
                souborů
              </span>
              <span>
                <strong>
                  <Count value={summary.findings.length} />
                </strong>
                nálezů
              </span>
              <span>
                <strong>
                  <Count value={summary.skippedTotal} />
                </strong>
                přeskočeno
              </span>
            </div>
          </>
        ) : (
          <p className="muted">Zatím žádná kontrola. Spusťte ji tlačítkem nahoře.</p>
        )}
      </section>

      <section className="panel rules reveal d4" aria-labelledby="rules-title">
        <div className="card-title">
          <span className="icon-tile">
            <Icon name="chart" />
          </span>
          <h2 id="rules-title">Sada pravidel</h2>
          {pack?.testPack ? <span className="chip">testovací</span> : null}
        </div>
        {pack ? (
          <>
            <ul className="kv">
              <li>
                <span>Podpis Ed25519</span>
                <strong className="tone-text-good">
                  <Icon name="check" size={16} /> ověřen
                </strong>
              </li>
              <li>
                <span>Pravidel</span>
                <strong>
                  <Count value={pack.ruleCount} />
                </strong>
              </li>
              <li>
                <span>Verze</span>
                <strong>{pack.version}</strong>
              </li>
            </ul>
            <div className="meter">
              <span>Platnost do {formatDate(pack.expiresAtUnix * 1000)}</span>
              <strong>{Math.round(validity * 100)} %</strong>
              <div className="meter-track">
                <span className="meter-fill" ref={(el) => el?.style.setProperty("--fill", String(validity))} />
              </div>
            </div>
          </>
        ) : (
          <p className="muted">Sada pravidel není načtená.</p>
        )}
      </section>

      <section className="panel recent reveal d5" aria-labelledby="recent-title">
        <div className="card-title">
          <span className="icon-tile">
            <Icon name="clock" />
          </span>
          <h2 id="recent-title">Poslední události</h2>
          <button type="button" className="btn-link card-link" onClick={() => onNavigate("events")}>
            Zobrazit vše
          </button>
        </div>
        {events.length ? (
          <ol className="event-list">
            {events.slice(0, 5).map((event) => {
              const d = describeAuditEvent(event);
              return (
                <li key={event.seq} className={`tone-${eventTone(event)}`}>
                  <span className="dot" aria-hidden="true" />
                  <time>{formatTime(event.tsMs)}</time>
                  <span className="event-text">
                    {d.title}
                    {d.detail ? <span className="muted"> {d.detail}</span> : null}
                  </span>
                </li>
              );
            })}
          </ol>
        ) : (
          <p className="muted">Auditní log je prázdný.</p>
        )}
      </section>

      <div className="tiles">
        {TILES.map((tile, i) => (
          <button
          key={tile.n}
          type="button"
          className={`tile t${i + 1} reveal d${6 + i}${tile.planned ? " is-planned" : ""}`}
          onClick={() => onNavigate(tile.screen)}
        >
          <span className="tile-num">{tile.n}</span>
          <span className="tile-go" aria-hidden="true">
            <Icon name="chevron" />
          </span>
          <TileArt kind={tile.art} />
          <span className="tile-title">{tile.title}</span>
          <span className="tile-text">{tile.text}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
