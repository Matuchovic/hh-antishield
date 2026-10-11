import { memo, useMemo } from "react";
import { Backdrop } from "../components/Backdrop";
import { Emblem } from "../components/Emblem";
import { Icon, type IconName } from "../components/Icon";
import type { Screen } from "../components/Sidebar";
import { TileArt, type TileArtKind } from "../components/TileArt";
import {
  COMPONENT_LABELS,
  SHIELD_LAYERS,
  describeAuditEvent,
  describeOutcome,
  formatCount,
  formatDate,
  formatDateTime,
  formatTime,
  headline,
  platformName,
  relativeTime,
  stateTone,
  type Tone,
} from "../lib/format";
import type { AuditEvent, ComponentKind, ComponentState, ProtectionLevel } from "../lib/types";
import type { AntiShield } from "../lib/useAntiShield";
import { useCountUp } from "../lib/useCountUp";

const LAYERS: { kind: ComponentKind; icon: IconName; desc: string }[] = [
  { kind: "onDemandScan", icon: "search", desc: "Soubory, které vyberete" },
  { kind: "realTimeProtection", icon: "shield", desc: "Nové soubory ve složkách" },
  { kind: "webProtection", icon: "globe", desc: "Blokování webů" },
  { kind: "emailProtection", icon: "mail", desc: "Přílohy a odkazy" },
  { kind: "privacyProtection", icon: "lock", desc: "Osobní data" },
];

const HEALTH: { kind: ComponentKind; label: string }[] = [
  { kind: "detectionEngine", label: "Engine" },
  { kind: "rulePack", label: "Pravidla" },
  { kind: "updates", label: "Aktualizace" },
  { kind: "quarantine", label: "Karanténa" },
  { kind: "auditLog", label: "Audit" },
];

const PILL: Record<ProtectionLevel, { text: string; tone: Tone }> = {
  protected: { text: "Vše funguje správně", tone: "good" },
  monitored: { text: "Hlídání běží", tone: "good" },
  manualScanOnly: { text: "Jen ruční kontrola", tone: "caution" },
  notReady: { text: "Kontrola není připravená", tone: "alert" },
};

const TILES: { n: string; title: string; text: string; art: TileArtKind; screen: Screen }[] = [
  { n: "01", title: "Kontrola počítače", text: "Rychlá, úplná nebo jen vybrané složky.", art: "folder", screen: "scan" },
  { n: "02", title: "Ochrana v reálném čase", text: "Hlídá stažené soubory, Plochu, Dokumenty a spuštěné programy.", art: "lock", screen: "realtime" },
  { n: "03", title: "Bezpečnost systému", text: "Gatekeeper, SIP, FileVault a firewall.", art: "wrench", screen: "systemcare" },
];

function layerText(kind: ComponentKind, state: ComponentState): string {
  switch (state.type) {
    case "running":
      return kind === "onDemandScan" ? "Připraveno" : "Aktivní";
    case "notImplemented":
      return "Zatím není";
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
    case "quarantine_failed":
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

/** Pozadí karty se mění jen se stavem kontroly, ne s každým průběhem. */
const HeroBackdrop = memo(function HeroBackdrop({ intense, still }: { intense: boolean; still: boolean }) {
  return <Backdrop intense={intense} still={still} />;
});

export function Overview({ app, onNavigate }: { app: AntiShield; onNavigate: (s: Screen) => void }) {
  const { protection, summary, events, info, scan, runtime } = app;
  const components = protection?.components;
  const layers = useMemo(
    () =>
      SHIELD_LAYERS.map((kind) => {
        const state = components?.find((c) => c.kind === kind)?.state;
        return state ? stateTone(state) : "off";
      }).join(","),
    [components],
  );
  if (!protection) {
    return <p className="muted">Načítám stav enginu…</p>;
  }
  const device = info?.platform.startsWith("macos") ? "Mac" : "počítač";
  const h = headline(protection.level, protection.components, device);
  const ready = protection.level !== "notReady";
  const pill = PILL[protection.level];
  const stateOf = (kind: ComponentKind) =>
    protection.components.find((c) => c.kind === kind)?.state ?? ({ type: "notImplemented" } as ComponentState);

  const pending = summary?.findings.filter((f) => app.cleaning[f.path] === undefined) ?? [];
  // Nevyčištěné skutečné nálezy mají přednost před běžným stavem ochrany.
  const threats = scan.running ? [] : pending.filter((f) => !f.testOnly);
  const tone = scan.running ? "good" : threats.length ? "alert" : h.tone;
  const title = scan.running ? "Kontrola právě běží" : threats.length ? "Pozor, nalezené hrozby" : h.title;
  const words = title.split(" ");
  const accent = words.pop() ?? "";
  const detail = scan.running
    ? `Zkontrolováno ${formatCount(scan.progress?.filesScanned ?? 0, "soubor", "soubory", "souborů")}.`
    : threats.length
      ? `${formatCount(threats.length, "nález čeká", "nálezy čekají", "nálezů čeká")} na vyčištění. Vyčištění je přesune do karantény, odkud je jde obnovit.`
      : h.detail;

  const pack = info?.rulePack;
  const validity = pack
    ? Math.max(0, Math.min(1, (pack.expiresAtUnix - Date.now() / 1000) / Math.max(1, pack.expiresAtUnix - pack.createdAtUnix)))
    : 0;

  return (
    <div className="overview">
      <section className={`hero reveal d1 tone-${tone}`} aria-labelledby="hero-title">
        <HeroBackdrop intense={scan.running} still={Boolean(app.settings?.reducedMotion)} />
        <p className="hero-tag left">
          <strong>H&amp;H AntiShield</strong>
          <br />
          Antivirus &amp; System Protection
        </p>
        <p className="hero-tag right">
          <strong>Verze {__APP_VERSION__}</strong>
          <br />
          {info ? platformName(info.platform) : ""}
        </p>
        <Emblem layers={layers} scanning={scan.running} />
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
        ) : threats.length ? (
          <button type="button" className="cta cta-alert" onClick={() => void app.remediate(threats.map((f) => f.path))}>
            <Icon name="sparkle" size={22} />
            <span>Vyčistit vše</span>
            <Icon name="chevron" size={20} className="cta-chev" />
          </button>
        ) : (
          <>
            <button type="button" className="cta" disabled={!ready} onClick={() => void app.startPreset("quick")}>
              <Icon name="bolt" size={22} />
              <span>Rychlá kontrola</span>
              <Icon name="chevron" size={20} className="cta-chev" />
            </button>
            <p className="hero-alt">
              nebo{" "}
              <button type="button" className="btn-link" onClick={() => onNavigate("scan")}>
                úplná a vlastní kontrola
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
            const desc =
              layer.kind === "realTimeProtection" && runtime?.watched.length
                ? `Hlídá ${formatCount(runtime.watched.length, "složku", "složky", "složek")}${runtime.programsSinceMs ? " a programy" : ""}`
                : layer.desc;
            return (
              <li key={layer.kind} className={`layer-row tone-${stateTone(state)}`}>
                <span className="icon-tile">
                  <Icon name={layer.icon} />
                </span>
                <span>
                  <span className="layer-name">{COMPONENT_LABELS[layer.kind]}</span>
                  <span className="layer-desc">{desc}</span>
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
            <p className={pending.length ? "tone-text-alert" : "muted"}>
              {pending.length
                ? `${formatCount(pending.length, "nález čeká", "nálezy čekají", "nálezů čeká")} na vyčištění.`
                : `${describeOutcome(summary.outcome)}, žádná hrozba nečeká.`}
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
            {pending.length ? (
              <button type="button" className="btn-danger" onClick={() => void app.remediate(pending.map((f) => f.path))}>
                <Icon name="sparkle" size={18} /> Vyčistit vše
              </button>
            ) : null}
          </>
        ) : (
          <p className="muted">Zatím žádná kontrola. Spusťte rychlou kontrolu tlačítkem nahoře.</p>
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
                <span>Pravidel YARA</span>
                <strong>
                  <Count value={pack.yaraRuleCount} />
                </strong>
              </li>
              <li>
                <span>Aktualizace</span>
                <strong>{runtime?.rules.lastSuccessMs ? relativeTime(runtime.rules.lastSuccessMs) : "zatím ne"}</strong>
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
          <p className="muted">Sada pravidel se načítá…</p>
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
            className={`tile t${i + 1} reveal d${6 + i}`}
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
