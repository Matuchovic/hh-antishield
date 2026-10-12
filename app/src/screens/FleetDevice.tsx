import { useEffect, useMemo, useState, type CSSProperties, type ReactNode } from "react";
import { Gauge } from "../components/Gauge";
import { Icon, type IconName } from "../components/Icon";
import { PRESSURE_TEXT, cpuTone, diskTone, memoryTone, uptimeText, uptimeTone } from "../lib/care";
import {
  activeThreats,
  agoText,
  categoryBytes,
  categoryList,
  commandInProgress,
  commandStatus,
  commandTitle,
  compareVersions,
  connectionText,
  cpuText,
  deepNowBytes,
  describeFleetEvent,
  deviceHealth,
  groupFingerprint,
  hasAction,
  initials,
  isExtended,
  isOnline,
  offersMore,
  pending,
  policyOffer,
  policyRule,
  recommendations,
  securityChecks,
  shares,
  supportsExtended,
  EXTENDED_SINCE,
  type DeviceTab,
  type FleetTone,
  type Health,
  type RecAction,
  type SecurityCheck,
} from "../lib/fleet";
import { displayPath, formatBytes, formatCount, formatDate, formatDateTime, formatRam, formatTime, translateReason } from "../lib/format";
import { SEVERITY_LABELS, fileName } from "../lib/story";
import type { CleanCategory, FleetAdmin, FleetCommandKind, FleetCommandOptions, FleetDevice } from "../lib/types";

type Send = (kind: FleetCommandKind, categories: CleanCategory[], options?: FleetCommandOptions) => Promise<void>;

const KIND_ICON: Record<FleetCommandKind, IconName> = {
  cleanup: "sparkle",
  scan: "search",
  isolate: "box",
  restart: "power",
  quitApps: "close",
  update: "download",
  deleteQuarantine: "trash",
  policy: "key",
};

const TABS: { id: DeviceTab; label: string; icon: IconName }[] = [
  { id: "overview", label: "Přehled", icon: "home" },
  { id: "care", label: "Údržba", icon: "sparkle" },
  { id: "security", label: "Zabezpečení", icon: "shield" },
  { id: "performance", label: "Výkon", icon: "gauge" },
  { id: "threats", label: "Hrozby", icon: "warning" },
  { id: "hardware", label: "Hardware", icon: "laptop" },
  { id: "history", label: "Historie", icon: "clock" },
];

/** Prstenec celkového stavu. */
function HealthRing({ health }: { health: Health }) {
  const r = 46;
  const circle = 2 * Math.PI * r;
  const fill = (Math.max(0, Math.min(100, health.score)) / 100) * circle;
  return (
    <figure className={`health-ring tone-${health.tone}`} aria-label={`Celkový stav ${health.score} ze 100`}>
      <svg viewBox="0 0 112 112" aria-hidden="true">
        <circle className="health-track" cx="56" cy="56" r={r} />
        <circle className="health-fill" cx="56" cy="56" r={r} strokeDasharray={`${fill} ${circle}`} />
      </svg>
      <div className="health-center">
        <span className="health-score">{health.score}</span>
        <span className="health-of">ze 100</span>
      </div>
      <figcaption>{health.label}</figcaption>
    </figure>
  );
}

function Section({ title, aside, children, className }: { title: string; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`panel device-section${className ? ` ${className}` : ""}`}>
      <div className="panel-head">
        <h2>{title}</h2>
        {aside}
      </div>
      {children}
    </section>
  );
}

/** Obsah, který Mac posílá jen s rozšířenou správou. */
function NotShared({ what }: { what: string }) {
  return (
    <p className="device-locked">
      <Icon name="lock" size={18} />
      <span>
        {what} Mac posílá jen s rozšířenou správou, kterou musí potvrdit jeho uživatel.
      </span>
    </p>
  );
}

function StatusPill({ tone, children }: { tone: FleetTone | "off" | "busy"; children: ReactNode }) {
  return (
    <span className={`status-pill tone-${tone}`}>
      <span className="dot" aria-hidden="true" />
      {children}
    </span>
  );
}

function CommandState({ kind, device }: { kind: FleetCommandKind; device: FleetDevice }) {
  const running = pending(device, kind);
  if (!running) return null;
  const status = commandStatus(running);
  return (
    <span className="device-running">
      <span className="spinner" aria-hidden="true" />
      {status.text}
    </span>
  );
}

export function FleetDevicePage({
  device,
  fleet,
  now,
  busy,
  latest,
  onBack,
  onSend,
  onRemove,
}: {
  device: FleetDevice;
  fleet: FleetAdmin;
  now: number;
  busy: boolean;
  latest: string;
  onBack: () => void;
  onSend: Send;
  onRemove: () => Promise<void>;
}) {
  const [tab, setTab] = useState<DeviceTab>("overview");
  const report = device.report;
  const policy = device.policy;
  const health = deviceHealth(device, latest, now);
  const recs = recommendations(device, latest, now);
  const online = isOnline(device, now);
  const offer = policyOffer(device);
  const extended = isExtended(policy);
  const security = report?.security ? securityChecks(report.security, now) : [];
  const securityOff = security.filter((c) => c.state === "off").length;
  const threatCount = activeThreats(report) + (report?.quarantine?.length ?? report?.quarantined ?? 0);
  const disabled = busy || device.left;

  // Klávesy ← a → mezi záložkami.
  const move = (dir: number) => {
    const index = TABS.findIndex((t) => t.id === tab);
    const next = TABS[(index + dir + TABS.length) % TABS.length];
    if (next) {
      setTab(next.id);
      document.getElementById(`device-tab-${next.id}`)?.focus();
    }
  };

  const act = (action: RecAction) => void onSend(action.kind, action.categories ?? [], action.options);

  const badge = (id: DeviceTab): number | null => {
    if (id === "security") return securityOff || null;
    if (id === "threats") return threatCount || null;
    if (id === "history") return device.commands.length || null;
    return null;
  };

  return (
    <div className="screen fleet-device">
      <button type="button" className="device-back" onClick={onBack}>
        <Icon name="chevron" size={18} />
        Firemní Macy
      </button>

      <header className={`panel device-hero tone-${health.tone}`} aria-labelledby="device-title">
        <div className="device-hero-main">
          <span className={`fleet-avatar device-avatar tone-${health.tone}${online ? " is-online" : ""}`} aria-hidden="true">
            {initials(device.name)}
          </span>
          <div className="device-hero-text">
            <h1 id="device-title">{device.name}</h1>
            <p className="device-model">
              {report ? (
                <>
                  {report.model}
                  <span className="sep">·</span>
                  {report.osVersion}
                  <span className="sep">·</span>
                  AntiShield {report.appVersion}
                </>
              ) : (
                "Mac zatím neposlal svůj stav."
              )}
            </p>
            <p className="device-meta">
              <StatusPill tone={online ? "good" : device.left ? "off" : "caution"}>
                {connectionText(device, now)}
                {report && !device.left ? ` · stav ověřený podpisem ${agoText(report.createdAtMs, now)}` : ""}
              </StatusPill>
              <span className={`policy-pill${extended ? " is-on" : ""}`}>
                <Icon name="key" size={14} />
                {extended ? "Rozšířená správa" : "Základní správa"}
              </span>
            </p>
          </div>
          <HealthRing health={health} />
        </div>
        {health.factors.length && report ? (
          <ul className="device-factors" aria-label="Co snižuje celkový stav">
            {health.factors.slice(0, 4).map((f) => (
              <li key={f.text}>
                <span className="factor-points">−{f.points}</span>
                {f.text}
              </li>
            ))}
          </ul>
        ) : null}
        <div className="device-quick">
          <button
            type="button"
            className="care-cta"
            disabled={disabled || commandInProgress(pending(device, "cleanup") ?? undefined) || !report}
            onClick={() => setTab("care")}
          >
            <Icon name="sparkle" />
            Údržba
            {deepNowBytes(device) > 0 ? <span className="cta-sub">{formatBytes(deepNowBytes(device))} hned</span> : null}
          </button>
          <button
            type="button"
            className="btn-secondary"
            disabled={disabled || pending(device, "scan") !== null}
            onClick={() => void onSend("scan", [])}
          >
            <Icon name="search" size={18} />
            Zkontrolovat
          </button>
          {hasAction(policy, "restart") ? (
            <button
              type="button"
              className="btn-secondary"
              disabled={disabled || pending(device, "restart") !== null}
              onClick={() => void onSend("restart", [])}
            >
              <Icon name="power" size={18} />
              Restart
            </button>
          ) : null}
          {hasAction(policy, "updates") ? (
            <button
              type="button"
              className="btn-secondary"
              disabled={disabled || pending(device, "update") !== null}
              onClick={() => void onSend("update", [])}
            >
              <Icon name="download" size={18} />
              Aktualizovat
            </button>
          ) : null}
          <span className="device-quick-state">
            {device.commands[0] && commandInProgress(device.commands[0]) ? (
              <>
                <span className="spinner" aria-hidden="true" />
                {commandTitle(device.commands[0], policy)}: {commandStatus(device.commands[0]).text.toLowerCase()}
              </>
            ) : null}
          </span>
        </div>
      </header>

      {!device.left && report && (offersMore(fleet.policy, policy) || offer?.state === "awaitingConsent") ? (
        <ExtendedOffer device={device} fleet={fleet} now={now} busy={disabled} onSend={onSend} />
      ) : null}

      <nav className="device-tabs" role="tablist" aria-label="Části detailu Macu">
        {TABS.map((t) => {
          const count = badge(t.id);
          return (
            <button
              key={t.id}
              id={`device-tab-${t.id}`}
              type="button"
              role="tab"
              aria-selected={tab === t.id}
              aria-controls="device-panel"
              tabIndex={tab === t.id ? 0 : -1}
              className={`device-tab${tab === t.id ? " is-active" : ""}`}
              onClick={() => setTab(t.id)}
              onKeyDown={(e) => {
                if (e.key === "ArrowRight") move(1);
                if (e.key === "ArrowLeft") move(-1);
              }}
            >
              <Icon name={t.icon} size={16} />
              {t.label}
              {count ? <span className={`tab-badge${t.id === "history" ? "" : " is-hot"}`}>{count}</span> : null}
            </button>
          );
        })}
      </nav>

      <div id="device-panel" role="tabpanel" aria-labelledby={`device-tab-${tab}`} className="device-panel" key={tab}>
        {!report ? (
          <section className="panel">
            <p className="muted">Mac zatím neposlal svůj stav. Objeví se do minuty po připojení.</p>
          </section>
        ) : tab === "overview" ? (
          <Overview device={device} now={now} recs={recs} security={security} onAct={act} onTab={setTab} disabled={disabled} />
        ) : tab === "care" ? (
          <Care device={device} now={now} latest={latest} disabled={disabled} onSend={onSend} />
        ) : tab === "security" ? (
          <Security device={device} now={now} checks={security} />
        ) : tab === "performance" ? (
          <Performance device={device} now={now} disabled={disabled} onSend={onSend} />
        ) : tab === "threats" ? (
          <Threats device={device} now={now} disabled={disabled} onSend={onSend} />
        ) : tab === "hardware" ? (
          <Hardware device={device} now={now} />
        ) : (
          <History device={device} />
        )}
      </div>

      <RemoveFooter device={device} onRemove={onRemove} />
    </div>
  );
}

function ExtendedOffer({
  device,
  fleet,
  now,
  busy,
  onSend,
}: {
  device: FleetDevice;
  fleet: FleetAdmin;
  now: number;
  busy: boolean;
  onSend: Send;
}) {
  const offer = policyOffer(device);
  const waiting = offer && commandInProgress(offer);
  const declined = offer?.state === "declined";
  const first = device.name.split(/\s+/)[0] ?? device.name;
  // Starší AntiShield žádosti nerozumí: nejdřív aktualizace na Macu.
  const outdated = device.report && !supportsExtended(device.report) ? device.report.appVersion : null;
  return (
    <section className={`panel device-offer${waiting ? " is-waiting" : ""}`} aria-labelledby="offer-title">
      <span className="device-offer-icon" aria-hidden="true">
        <Icon name={outdated ? "download" : "key"} size={22} />
      </span>
      <div className="device-offer-text">
        <h2 id="offer-title">
          {outdated
            ? `Rozšířená správa potřebuje na Macu AntiShield ${EXTENDED_SINCE.replace(/\.0$/, "")} nebo novější`
            : waiting
              ? `Čeká na souhlas: ${first} rozhoduje o rozšířené správě`
              : declined
                ? `${first} rozšířenou správu odmítl(a) ${agoText(offer.updatedAtMs, now)}`
                : "Rozšířená správa zatím není potvrzená"}
        </h2>
        <p className="muted">
          {outdated
            ? `Na Macu běží AntiShield ${outdated}, který žádosti nerozumí. Ať ${first} v AntiShieldu klikne na Aktualizovat; pak tu o rozšířenou správu požádáte.`
            : waiting
              ? `Žádost odešla ${agoText(offer.sentAtMs, now)}. ${offer.state === "queued" ? "Mac je offline, žádost počká." : "Uživatel ji vidí v AntiShieldu."}`
              : "Přidá podrobnosti o hardwaru, zabezpečení, výkonu a hrozbách, hloubkový úklid, úplnou kontrolu, mazání z karantény a aktualizace. Restart, ukončení aplikací, Koš a velké soubory vždy jen se souhlasem uživatele."}
        </p>
      </div>
      {outdated ? null : waiting ? (
        <span className="device-running">
          <span className="spinner" aria-hidden="true" />
          {commandStatus(offer).text}
        </span>
      ) : (
        <button
          type="button"
          className="btn-secondary"
          disabled={busy || !offersMore(fleet.policy, device.policy)}
          onClick={() => void onSend("policy", [])}
        >
          {declined ? "Požádat znovu" : "Požádat o rozšířenou správu"}
        </button>
      )}
    </section>
  );
}

// ---------- Přehled ----------

function Overview({
  device,
  now,
  recs,
  security,
  onAct,
  onTab,
  disabled,
}: {
  device: FleetDevice;
  now: number;
  recs: ReturnType<typeof recommendations>;
  security: SecurityCheck[];
  onAct: (action: RecAction) => void;
  onTab: (tab: DeviceTab) => void;
  disabled: boolean;
}) {
  const report = device.report;
  if (!report) return null;
  const disk = report.disk;
  const perf = report.performance;
  const battery = report.hardware?.battery ?? null;
  const memTone = memoryTone({ ...report.memory, swapUsed: perf?.swapUsed ?? 0 });
  return (
    <div className="device-grid">
      <Section title="Stav" className="device-vitals span-2">
        <div className="gauges device-gauges is-still">
          <Gauge
            title="Volné místo"
            value={disk && disk.total > 0 ? 1 - disk.free / disk.total : 0}
            tone={diskTone(disk)}
            primary={disk ? formatBytes(disk.free) : "Neznámé"}
            secondary={disk ? `z ${formatBytes(disk.total)}` : ""}
          />
          <Gauge
            title="Paměť"
            value={report.memory.total > 0 ? report.memory.used / report.memory.total : 0}
            tone={memTone}
            primary={`${Math.round((report.memory.used / Math.max(1, report.memory.total)) * 100)} %`}
            secondary={report.memory.pressure ? PRESSURE_TEXT[report.memory.pressure] : formatRam(report.memory.total)}
          />
          {perf ? (
            <Gauge
              title="Procesor"
              value={perf.cpuPermille / 1000}
              tone={cpuTone(perf.cpuPermille / 10)}
              primary={cpuText(perf.cpuPermille)}
              secondary={formatCount(perf.cores, "jádro", "jádra", "jader")}
            />
          ) : null}
          {battery ? (
            <Gauge
              title="Baterie"
              value={(battery.healthPct ?? 0) / 100}
              tone={battery.service ? "caution" : "good"}
              primary={battery.healthPct !== null ? `${battery.healthPct} %` : "?"}
              secondary={`${formatCount(battery.cycles, "cyklus", "cykly", "cyklů")}`}
            />
          ) : null}
          <figure className={`uptime tone-${uptimeTone(report.uptimeSecs)}`}>
            <Icon name="clock" />
            <span className="uptime-value">{uptimeText(report.uptimeSecs)}</span>
            <figcaption>bez restartu</figcaption>
          </figure>
        </div>
      </Section>

      <Section title="Doporučení" className="device-recs" aside={recs.length ? <span className="muted">{recs.length}</span> : null}>
        {recs.length ? (
          <ul className="rec-list">
            {recs.map((rec) => (
              <li key={rec.id} className={`rec tone-${rec.tone}`}>
                <span className="rec-icon" aria-hidden="true">
                  <Icon name={rec.tone === "good" ? "sparkle" : "warning"} size={18} />
                </span>
                <span className="rec-text">
                  <strong>{rec.title}</strong>
                  <span>{rec.detail}</span>
                </span>
                <span className="rec-actions">
                  {rec.action ? (
                    <button type="button" className="btn-secondary btn-small" disabled={disabled} onClick={() => onAct(rec.action!)}>
                      {rec.action.label}
                    </button>
                  ) : null}
                  {rec.tab ? (
                    <button type="button" className="btn-link" onClick={() => onTab(rec.tab!)}>
                      Podrobnosti
                    </button>
                  ) : null}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="rec-empty">
            <Icon name="check" size={18} /> Mac nic nepotřebuje. Všechno, co posílá, je v pořádku.
          </p>
        )}
      </Section>

      <div className="device-stack">
        <Section title="Ochrana">
          <dl className="fleet-facts">
            <div>
              <dt>Hlídání</dt>
              <dd>
                {report.protection === "monitored" || report.protection === "protected"
                  ? "Běží"
                  : report.protection === "manualScanOnly"
                    ? "Omezené, jen ruční kontrola"
                    : "Nefunguje"}
                {report.protectionNote ? <span className="muted"> · {translateReason(report.protectionNote)}</span> : null}
              </dd>
            </div>
            <div>
              <dt>Pravidla</dt>
              <dd>
                {report.rulesVersion}
                {report.rulesCheckedAtMs ? <span className="muted"> · ověřena {agoText(report.rulesCheckedAtMs, now)}</span> : null}
              </dd>
            </div>
            <div>
              <dt>Poslední kontrola</dt>
              <dd>
                {report.lastScan ? (
                  <>
                    {formatDateTime(report.lastScan.atMs)}
                    <span className="muted">
                      {" "}
                      · {formatCount(report.lastScan.files, "soubor", "soubory", "souborů")},{" "}
                      {report.lastScan.threats ? formatCount(report.lastScan.threats, "nález", "nálezy", "nálezů") : "bez nálezu"}
                    </span>
                  </>
                ) : (
                  "Zatím žádná"
                )}
              </dd>
            </div>
            <div>
              <dt>Karanténa</dt>
              <dd>{report.quarantined ? formatCount(report.quarantined, "položka", "položky", "položek") : "Prázdná"}</dd>
            </div>
          </dl>
        </Section>

        <Section
          title="Zabezpečení systému"
          aside={
            security.length ? (
              <button type="button" className="btn-link" onClick={() => onTab("security")}>
                Vše
              </button>
            ) : null
          }
        >
          {security.length ? (
            <ul className="check-mini">
              {security.map((c) => (
                <li key={c.id} className={`is-${c.state}`}>
                  <Icon name={c.state === "on" ? "check" : c.state === "off" ? "warning" : "info"} size={16} />
                  <span>{c.title}</span>
                  <em>{c.label}</em>
                </li>
              ))}
            </ul>
          ) : (
            <NotShared what="Stav FileVaultu, firewallu, aktualizací a zálohy" />
          )}
        </Section>
      </div>
    </div>
  );
}

// ---------- Údržba ----------

type CareRow = {
  id: string;
  category: CleanCategory | null;
  title: string;
  detail: string;
  bytes: number;
  rule: "now" | "consent" | "pick";
  available: boolean;
  /** Nedá se vybrat zvlášť: jde s řádkem `follows`. */
  follows?: string;
};

function Care({
  device,
  now,
  latest,
  disabled,
  onSend,
}: {
  device: FleetDevice;
  now: number;
  latest: string;
  disabled: boolean;
  onSend: Send;
}) {
  const report = device.report;
  const policy = device.policy;
  const deepAllowed = hasAction(policy, "deepClean");
  const deep = report?.cleanup?.deep ?? null;
  const consentAllowed = (c: CleanCategory) => policyRule(policy, c) === "consent";
  const installers = categoryBytes(report, "installers").bytes + categoryBytes(report, "leftovers").bytes;
  const trash = categoryBytes(report, "trash");
  const large = categoryBytes(report, "largeFiles");
  const rows: CareRow[] = [
    {
      id: "auto",
      category: null,
      title: deepAllowed ? "Mezipaměti, protokoly a vývojářská data" : "Mezipaměti, protokoly a vývojářské mezipaměti",
      detail: deepAllowed
        ? "Hloubkově: i čerstvé mezipaměti aplikací, které neběží. Smaže se hned, aplikace si je vytvoří znovu."
        : "Jen to, co se 15 minut nepoužilo a nepatří běžící aplikaci.",
      bytes: deepNowBytes(device),
      rule: "now",
      available: true,
    },
    ...(deepAllowed && deep && deep.appsBytes > 0
      ? [
          {
            id: "apps",
            category: null,
            title: `Mezipaměti ${formatCount(deep.apps, "běžící aplikace", "běžících aplikací", "běžících aplikací")}`,
            detail: "Patří k položce výše. Uživatel uvidí, které aplikace se zavřou, a sám potvrdí; aplikace se zeptají na uložení práce.",
            bytes: deep.appsBytes,
            rule: "consent" as const,
            available: true,
            follows: "auto",
          },
        ]
      : []),
    {
      id: "installers",
      category: "installers",
      title: "Staré instalátory a zbytky po aplikacích",
      detail: "Přesunou se do Koše, odkud je jde vrátit.",
      bytes: installers,
      rule: "consent",
      available: consentAllowed("installers") && installers > 0,
    },
    {
      id: "trash",
      category: "trash",
      title: "Vysypat Koš",
      detail: trash.items ? `${formatCount(trash.items, "soubor", "soubory", "souborů")} · nevratné, uživatel to výslovně potvrdí.` : "Nevratné, uživatel to výslovně potvrdí.",
      bytes: trash.bytes,
      rule: "consent",
      available: consentAllowed("trash") && trash.bytes > 0,
    },
    {
      id: "largeFiles",
      category: "largeFiles",
      title: "Velké staré soubory",
      detail: large.items
        ? `${formatCount(large.items, "soubor", "soubory", "souborů")} nad 1 GB. Uživatel vybere, které přesunout do Koše; názvy vidí jen on.`
        : "Soubory nad 1 GB půl roku beze změny. Vybírá je uživatel.",
      bytes: large.bytes,
      rule: "pick",
      available: consentAllowed("largeFiles") && large.bytes > 0,
    },
  ];
  const [chosen, setChosen] = useState<Set<string>>(() => new Set(["auto", "installers"]));
  const toggle = (id: string) =>
    setChosen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const isPicked = (row: CareRow) => row.available && chosen.has(row.follows ?? row.id);
  const picked = rows.filter(isPicked);
  const nowBytes = picked.filter((r) => r.rule === "now").reduce((s, r) => s + r.bytes, 0);
  const laterBytes = picked.filter((r) => r.rule !== "now").reduce((s, r) => s + r.bytes, 0);
  const categories: CleanCategory[] = [
    ...(chosen.has("auto") ? policy.auto : []),
    ...(chosen.has("installers") && consentAllowed("installers") ? (["installers", "leftovers"] as CleanCategory[]) : []),
    ...(chosen.has("trash") && consentAllowed("trash") ? (["trash"] as CleanCategory[]) : []),
    ...(chosen.has("largeFiles") && consentAllowed("largeFiles") ? (["largeFiles"] as CleanCategory[]) : []),
  ].filter((c) => policyRule(policy, c) !== "never");
  const running = pending(device, "cleanup");
  const disk = report?.disk ?? null;
  const used = disk ? disk.total - disk.free : 0;
  const segments = rows
    .filter((r) => r.available && r.bytes > 0)
    .map((r) => ({ ...r, share: disk && disk.total > 0 ? r.bytes / disk.total : 0 }));
  const cleanupRun = () => void onSend("cleanup", categories, deepAllowed && chosen.has("auto") ? { deep: true } : undefined);

  return (
    <div className="device-grid">
      <Section title="Úložiště" className="span-2" aside={report?.cleanup ? <span className="muted">změřeno {agoText(report.cleanup.measuredAtMs, now)}</span> : null}>
        {disk ? (
          <>
            <div className="storage-bar" role="img" aria-label={`Obsazeno ${formatBytes(used)} z ${formatBytes(disk.total)}`}>
              <span className="storage-used" style={{ width: `${Math.min(100, (used / disk.total) * 100)}%` }}>
                {segments.map((s) => (
                  <span
                    key={s.id}
                    className={`storage-seg is-${s.rule}`}
                    style={{ width: `${Math.max(0.6, (s.share / Math.max(0.001, used / disk.total)) * 100)}%` }}
                    title={`${s.title}: ${formatBytes(s.bytes)}`}
                  />
                ))}
              </span>
            </div>
            <div className="storage-legend">
              <span>
                <strong>{formatBytes(used)}</strong> obsazeno
              </span>
              <span>
                <strong>{formatBytes(disk.free)}</strong> volno z {formatBytes(disk.total)}
              </span>
              <span className="legend-key is-now">hned</span>
              <span className="legend-key is-consent">se souhlasem</span>
              <span className="legend-key is-pick">vybere uživatel</span>
            </div>
          </>
        ) : (
          <p className="muted">Velikost disku Mac neposlal.</p>
        )}
      </Section>

      <Section
        title={deepAllowed ? "Hloubková údržba" : "Úklid"}
        className="span-2 device-maintain"
        aside={running ? <CommandState kind="cleanup" device={device} /> : null}
      >
        <ul className="maintain-list">
          {rows.map((row) => {
            const body = (
              <>
                <span className="maintain-text">
                  <strong>{row.title}</strong>
                  <span>{row.available || row.bytes > 0 ? row.detail : row.rule === "now" ? row.detail : "Na Macu nic není, nebo to zásady Macu nedovolují."}</span>
                </span>
                <span className={`rule-badge is-${row.rule}`}>
                  {row.rule === "now" ? "Hned" : row.rule === "consent" ? "Se souhlasem" : "Vybere uživatel"}
                </span>
                <span className="maintain-size">{formatBytes(row.bytes)}</span>
              </>
            );
            return (
              <li
                key={row.id}
                className={`maintain-row${row.available ? "" : " is-off"}${row.follows ? " is-follow" : ""}${isPicked(row) ? " is-picked" : ""}`}
              >
                {row.follows ? (
                  <div className="maintain-line">
                    <span className="follow-mark" aria-hidden="true">
                      ↳
                    </span>
                    {body}
                  </div>
                ) : (
                  <label className="maintain-line">
                    <input
                      type="checkbox"
                      checked={isPicked(row)}
                      disabled={!row.available || disabled}
                      onChange={() => toggle(row.id)}
                    />
                    {body}
                  </label>
                )}
              </li>
            );
          })}
        </ul>
        <div className="maintain-foot">
          <p>
            Hned <strong>{formatBytes(nowBytes)}</strong>
            {laterBytes ? (
              <>
                {" "}
                · po souhlasu uživatele až <strong>{formatBytes(laterBytes)}</strong>
              </>
            ) : null}
          </p>
          <button type="button" className="care-cta btn-cta-small" disabled={disabled || running !== null || categories.length === 0} onClick={cleanupRun}>
            <Icon name="sparkle" />
            {deepAllowed ? "Spustit hloubkovou údržbu" : "Uklidit na dálku"}
          </button>
        </div>
        <p className="care-note">
          Mac si vše před úklidem znovu najde sám. Mezipaměti běžících aplikací nesmaže bez jejich zavření, systémové soubory,
          dokumenty a fotky nikdy. Uživatel dostane oznámení o každém zásahu.
        </p>
      </Section>

      <SystemCards device={device} now={now} latest={latest} disabled={disabled} onSend={onSend} />
    </div>
  );
}

function SystemCards({
  device,
  now,
  latest,
  disabled,
  onSend,
}: {
  device: FleetDevice;
  now: number;
  latest: string;
  disabled: boolean;
  onSend: Send;
}) {
  const report = device.report;
  if (!report) return null;
  const p = device.policy;
  const restart = pending(device, "restart");
  const outdated = compareVersions(report.appVersion, latest) < 0;
  return (
    <div className="system-cards span-2">
      <section className={`panel system-card tone-${uptimeTone(report.uptimeSecs)}`}>
        <span className="system-icon" aria-hidden="true">
          <Icon name="power" size={22} />
        </span>
        <h2>Restart</h2>
        <p className="system-figure">{uptimeText(report.uptimeSecs)}</p>
        <p className="muted">bez restartu{report.uptimeSecs > 7 * 86_400 ? ", restart uvolní paměť a dokončí aktualizace" : ""}</p>
        {hasAction(p, "restart") ? (
          restart ? (
            <CommandState kind="restart" device={device} />
          ) : (
            <button type="button" className="btn-secondary btn-small" disabled={disabled} onClick={() => void onSend("restart", [])}>
              Požádat o restart
            </button>
          )
        ) : (
          <p className="system-locked">Vyžaduje rozšířenou správu</p>
        )}
        {restart?.untilMs ? <p className="muted">Odloženo do {formatTime(restart.untilMs)}</p> : null}
      </section>
      <section className={`panel system-card tone-${outdated ? "caution" : "good"}`}>
        <span className="system-icon" aria-hidden="true">
          <Icon name="download" size={22} />
        </span>
        <h2>Aktualizace</h2>
        <p className="system-figure">AntiShield {report.appVersion}</p>
        <p className="muted">
          {outdated ? `Nejnovější je ${latest}` : "Nejnovější verze"} · pravidla {report.rulesVersion}
          {report.rulesCheckedAtMs ? `, ověřena ${agoText(report.rulesCheckedAtMs, now)}` : ""}
        </p>
        {hasAction(p, "updates") ? (
          pending(device, "update") ? (
            <CommandState kind="update" device={device} />
          ) : (
            <button type="button" className="btn-secondary btn-small" disabled={disabled} onClick={() => void onSend("update", [])}>
              Aktualizovat AntiShield a pravidla
            </button>
          )
        ) : (
          <p className="system-locked">Vyžaduje rozšířenou správu</p>
        )}
      </section>
      <section className="panel system-card tone-good">
        <span className="system-icon" aria-hidden="true">
          <Icon name="search" size={22} />
        </span>
        <h2>Kontrola</h2>
        <p className="system-figure">{report.lastScan ? agoText(report.lastScan.atMs, now) : "Zatím žádná"}</p>
        <p className="muted">
          {report.lastScan
            ? `${formatCount(report.lastScan.files, "soubor", "soubory", "souborů")}, ${report.lastScan.threats ? formatCount(report.lastScan.threats, "nález", "nálezy", "nálezů") : "bez nálezu"}`
            : "Rychlá kontrola trvá pár minut."}
        </p>
        {pending(device, "scan") ? (
          <CommandState kind="scan" device={device} />
        ) : (
          <div className="actions">
            <button type="button" className="btn-secondary btn-small" disabled={disabled} onClick={() => void onSend("scan", [])}>
              Rychlá
            </button>
            {hasAction(p, "fullScan") ? (
              <button type="button" className="btn-secondary btn-small" disabled={disabled} onClick={() => void onSend("scan", [], { full: true })}>
                Úplná
              </button>
            ) : null}
          </div>
        )}
      </section>
    </div>
  );
}

// ---------- Zabezpečení ----------

function Security({ device, now, checks }: { device: FleetDevice; now: number; checks: SecurityCheck[] }) {
  const report = device.report;
  const security = report?.security;
  if (!report || !security || !shares(device.policy, "security")) {
    return (
      <div className="device-grid">
        <Section title="Zabezpečení systému" className="span-2">
          <NotShared what="Stav FileVaultu, firewallu, SIP, Gatekeeperu, aktualizací macOS a zálohy" />
        </Section>
      </div>
    );
  }
  const off = checks.filter((c) => c.state === "off").length;
  return (
    <div className="device-grid">
      <Section
        title="Ochrany systému"
        className="span-2"
        aside={<StatusPill tone={off ? "caution" : "good"}>{off ? `${off} k nápravě` : "Vše zapnuté"}</StatusPill>}
      >
        <ul className="check-list">
          {checks.map((c) => (
            <li key={c.id} className={`check-row is-${c.state} weight-${c.weight}`}>
              <span className="check-icon" aria-hidden="true">
                <Icon name={c.state === "on" ? "check" : c.state === "off" ? "warning" : "info"} size={18} />
              </span>
              <span className="check-text">
                <strong>{c.title}</strong>
                <span>{c.detail}</span>
                {c.state === "off" ? <span className="check-advice">{c.advice}</span> : null}
              </span>
              <span className={`check-state is-${c.state}`}>{c.label}</span>
            </li>
          ))}
        </ul>
        <p className="care-note">
          Ochrany systému AntiShield na dálku nemění. Pošlete uživateli postup u položky, kterou má zapnout.
        </p>
      </Section>
      {security.osUpdates?.length ? (
        <Section title="Čekající aktualizace macOS">
          <ul className="update-list">
            {security.osUpdates.map((u) => (
              <li key={u.title}>
                <Icon name="download" size={16} />
                <span>
                  <strong>{u.title}</strong>
                  {u.version ? <span className="muted"> {u.version}</span> : null}
                </span>
                {u.restart ? <em>vyžaduje restart</em> : null}
                {u.recommended ? <em className="is-hot">doporučená</em> : null}
              </li>
            ))}
          </ul>
        </Section>
      ) : null}
      <Section title="Vestavěná ochrana Applu">
        <dl className="fleet-facts">
          <div>
            <dt>XProtect</dt>
            <dd>{security.xprotect ? `definice ${security.xprotect}` : "Nezjištěno"}</dd>
          </div>
          <div>
            <dt>Neviditelný režim</dt>
            <dd>{security.stealth === null ? "Nezjištěno" : security.stealth ? "Zapnutý" : "Vypnutý"}</dd>
          </div>
          <div>
            <dt>Záloha</dt>
            <dd>
              {security.backup?.lastMs ? formatDateTime(security.backup.lastMs) : security.backup?.configured ? "Zatím žádná" : "Nenastavená"}
              {security.backup?.lastMs ? <span className="muted"> · {agoText(security.backup.lastMs, now)}</span> : null}
            </dd>
          </div>
        </dl>
      </Section>
    </div>
  );
}

// ---------- Výkon ----------

function Performance({
  device,
  now,
  disabled,
  onSend,
}: {
  device: FleetDevice;
  now: number;
  disabled: boolean;
  onSend: Send;
}) {
  const report = device.report;
  const perf = report?.performance;
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const canQuit = hasAction(device.policy, "quitApps");
  const quitting = pending(device, "quitApps");
  if (!report || !perf) {
    return (
      <div className="device-grid">
        <Section title="Výkon" className="span-2">
          <NotShared what="Vytížení procesoru, nejnáročnější aplikace a položky po přihlášení" />
        </Section>
      </div>
    );
  }
  const maxMemory = Math.max(1, ...perf.apps.map((a) => a.memory));
  const toggle = (id: string) =>
    setPicked((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  return (
    <div className="device-grid">
      <Section title="Vytížení" className="span-2" aside={<span className="muted">změřeno {agoText(perf.measuredAtMs, now)}</span>}>
        <dl className="perf-stats">
          <div className={`tone-${cpuTone(perf.cpuPermille / 10)}`}>
            <dt>Procesor</dt>
            <dd>{cpuText(perf.cpuPermille)}</dd>
            <span>{formatCount(perf.cores, "jádro", "jádra", "jader")}</span>
          </div>
          <div className={`tone-${memoryTone({ ...report.memory, swapUsed: perf.swapUsed })}`}>
            <dt>Paměť</dt>
            <dd>{formatRam(report.memory.used)}</dd>
            <span>z {formatRam(report.memory.total)}{report.memory.pressure ? ` · ${PRESSURE_TEXT[report.memory.pressure].toLowerCase()}` : ""}</span>
          </div>
          <div className={perf.swapUsed > 2e9 ? "tone-caution" : "tone-good"}>
            <dt>Odkládání na disk</dt>
            <dd>{formatBytes(perf.swapUsed)}</dd>
            <span>{perf.swapUsed > 2e9 ? "Mac zpomaluje, paměti je málo" : "v pořádku"}</span>
          </div>
          <div className={`tone-${uptimeTone(report.uptimeSecs)}`}>
            <dt>Bez restartu</dt>
            <dd>{uptimeText(report.uptimeSecs)}</dd>
            <span>od {formatDateTime(report.createdAtMs - report.uptimeSecs * 1000)}</span>
          </div>
        </dl>
      </Section>

      <Section
        title="Aplikace podle paměti"
        className="span-2"
        aside={quitting ? <CommandState kind="quitApps" device={device} /> : null}
      >
        <table className="device-table">
          <thead>
            <tr>
              {canQuit ? <th aria-label="Vybrat" /> : null}
              <th>Aplikace</th>
              <th className="num">Procesor</th>
              <th className="bar-col">Paměť</th>
              <th className="num">Procesy</th>
            </tr>
          </thead>
          <tbody>
            {perf.apps.map((app) => {
              const id = app.bundleId ?? app.name;
              return (
                <tr key={id} className={picked.has(id) ? "is-picked" : undefined}>
                  {canQuit ? (
                    <td>
                      <input
                        type="checkbox"
                        aria-label={`Vybrat ${app.name}`}
                        disabled={!app.bundleId || disabled || quitting !== null}
                        checked={picked.has(id)}
                        onChange={() => toggle(id)}
                      />
                    </td>
                  ) : null}
                  <td>
                    <strong>{app.name}</strong>
                    {app.bundleId ? <span className="muted cell-sub">{app.bundleId}</span> : null}
                  </td>
                  <td className="num">{cpuText(app.cpuPermille)}</td>
                  <td className="bar-col">
                    <span className="cell-bar" style={{ "--w": `${(app.memory / maxMemory) * 100}%` } as CSSProperties} />
                    {formatRam(app.memory)}
                  </td>
                  <td className="num">{app.processes}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {canQuit ? (
          <div className="maintain-foot">
            <p className="muted">Uživatel uvidí, které aplikace navrhujete ukončit, a rozhodne. Aplikace se zeptají na uložení práce.</p>
            <button
              type="button"
              className="btn-secondary"
              disabled={disabled || picked.size === 0 || quitting !== null}
              onClick={() => {
                void onSend("quitApps", [], { targets: [...picked] });
                setPicked(new Set());
              }}
            >
              <Icon name="close" size={16} />
              Navrhnout ukončení{picked.size ? ` (${picked.size})` : ""}
            </button>
          </div>
        ) : null}
      </Section>

      <Section title="Spouštění po přihlášení" className="span-2" aside={<span className="muted">{perf.loginItems.length}</span>}>
        {perf.loginItems.length ? (
          <table className="device-table">
            <thead>
              <tr>
                <th>Položka</th>
                <th>Program</th>
                <th>Stav</th>
              </tr>
            </thead>
            <tbody>
              {perf.loginItems.map((item) => (
                <tr key={item.label} className={item.enabled ? undefined : "is-dim"}>
                  <td>
                    <strong>{item.label}</strong>
                    {item.system ? <span className="muted cell-sub">pro celý systém</span> : null}
                  </td>
                  <td>{item.program ?? <span className="muted">—</span>}</td>
                  <td>
                    <StatusPill tone={!item.enabled ? "off" : item.running ? "good" : "caution"}>
                      {!item.enabled ? "Vypnutá" : item.running ? "Běží" : "Zapnutá"}
                    </StatusPill>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="muted">Po přihlášení se nic navíc nespouští.</p>
        )}
      </Section>
    </div>
  );
}

// ---------- Hrozby ----------

function Threats({
  device,
  now,
  disabled,
  onSend,
}: {
  device: FleetDevice;
  now: number;
  disabled: boolean;
  onSend: Send;
}) {
  const report = device.report;
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [confirm, setConfirm] = useState(false);
  useEffect(() => setConfirm(false), [picked]);
  const events = useMemo(() => report?.events ?? [], [report]);
  if (!report) return null;
  const threats = report.threats;
  const open = activeThreats(report);
  const quarantine = report.quarantine ?? [];
  const canDelete = hasAction(device.policy, "quarantineDelete");
  const deleting = pending(device, "deleteQuarantine");
  const shared = shares(device.policy, "threats");
  const toggle = (id: string) =>
    setPicked((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  return (
    <div className="device-grid">
      <Section
        title="Zachycené hrozby"
        className="span-2"
        aside={
          open ? (
            <button type="button" className="btn-danger btn-small" disabled={disabled || pending(device, "isolate") !== null} onClick={() => void onSend("isolate", [])}>
              Izolovat {formatCount(open, "hrozbu", "hrozby", "hrozeb")}
            </button>
          ) : null
        }
      >
        {threats.length ? (
          <ul className="fleet-threats">
            {threats.map((t) => (
              <li key={`${t.path}:${t.ruleName}`} className={t.quarantined ? "is-done" : undefined}>
                <Icon name={t.quarantined ? "box" : "warning"} size={18} />
                <span className="fleet-threat-text">
                  <strong>{t.ruleName}</strong>
                  <span className="item-path" title={displayPath(t.path)}>{`‎${displayPath(t.path)}‎`}</span>
                </span>
                <span className={`sev sev-${t.severity}`}>{SEVERITY_LABELS[t.severity]}</span>
                <span className="fleet-threat-state">{t.quarantined ? "V karanténě" : `Zachyceno ${agoText(t.detectedAtMs, now)}`}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="rec-empty">
            <Icon name="check" size={18} /> Žádná hrozba. {report.lastScan ? `Poslední kontrola ${agoText(report.lastScan.atMs, now)}.` : ""}
          </p>
        )}
      </Section>

      <Section
        title="Karanténa"
        className="span-2"
        aside={<span className="muted">{formatCount(report.quarantined, "položka", "položky", "položek")}</span>}
      >
        {!shared ? (
          <NotShared what="Názvy a důvody položek v karanténě" />
        ) : quarantine.length ? (
          <>
            <table className="device-table">
              <thead>
                <tr>
                  {canDelete ? <th aria-label="Vybrat" /> : null}
                  <th>Soubor</th>
                  <th>Důvod</th>
                  <th>Závažnost</th>
                  <th>Izolováno</th>
                  <th className="num">Velikost</th>
                </tr>
              </thead>
              <tbody>
                {quarantine.map((q) => (
                  <tr key={q.id} className={picked.has(q.id) ? "is-picked" : undefined}>
                    {canDelete ? (
                      <td>
                        <input
                          type="checkbox"
                          aria-label={`Vybrat ${fileName(q.path)}`}
                          disabled={disabled || deleting !== null}
                          checked={picked.has(q.id)}
                          onChange={() => toggle(q.id)}
                        />
                      </td>
                    ) : null}
                    <td>
                      <strong>{fileName(q.path)}</strong>
                      <span className="muted cell-sub item-path" title={displayPath(q.path)}>{`‎${displayPath(q.path)}‎`}</span>
                    </td>
                    <td>
                      {q.ruleName}
                      <span className="muted cell-sub" title={q.sha256}>
                        SHA-256 {q.sha256.slice(0, 12)}…
                      </span>
                    </td>
                    <td>
                      <span className={`sev sev-${q.severity}`}>{SEVERITY_LABELS[q.severity]}</span>
                    </td>
                    <td>{formatDate(q.atMs)}</td>
                    <td className="num">{formatBytes(q.size)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {canDelete ? (
              <div className="maintain-foot">
                <p className="muted">
                  {confirm
                    ? "Smazání z karantény je nevratné. Opravdu smazat?"
                    : "Soubory v karanténě jsou znehodnocené a nejdou spustit. Smazáním uvolníte místo."}
                </p>
                {confirm ? (
                  <div className="actions">
                    <button
                      type="button"
                      className="btn-danger"
                      onClick={() => {
                        void onSend("deleteQuarantine", [], { targets: [...picked] });
                        setPicked(new Set());
                      }}
                    >
                      Smazat {picked.size}
                    </button>
                    <button type="button" className="btn-link" onClick={() => setConfirm(false)}>
                      Zpět
                    </button>
                  </div>
                ) : deleting ? (
                  <CommandState kind="deleteQuarantine" device={device} />
                ) : (
                  <button type="button" className="btn-secondary" disabled={disabled || picked.size === 0} onClick={() => setConfirm(true)}>
                    <Icon name="trash" size={16} />
                    Smazat vybrané{picked.size ? ` (${picked.size})` : ""}
                  </button>
                )}
              </div>
            ) : null}
          </>
        ) : (
          <p className="muted">Karanténa je prázdná.</p>
        )}
      </Section>

      <Section title="Časová osa ochrany" className="span-2" aside={events.length ? <span className="muted">{events.length}</span> : null}>
        {!shared ? (
          <NotShared what="Události ochrany (nálezy, karanténa, kontroly, aktualizace pravidel)" />
        ) : events.length ? (
          <ol className="timeline">
            {events.map((event) => {
              const text = describeFleetEvent(event);
              const tone =
                event.kind === "finding" || event.kind === "quarantine_failed" || event.kind === "audit_integrity_issue"
                  ? "alert"
                  : event.kind.startsWith("quarantine") || event.kind === "rule_pack_rejected"
                    ? "caution"
                    : "good";
              return (
                <li key={`${event.atMs}:${event.kind}:${text.detail}`} className={`tone-${tone}`}>
                  <time dateTime={new Date(event.atMs).toISOString()}>{formatDateTime(event.atMs)}</time>
                  <span className="timeline-dot" aria-hidden="true" />
                  <span className="timeline-text">
                    <strong>{text.title}</strong>
                    {text.detail ? <span className="item-path">{`\u200e${text.detail}\u200e`}</span> : null}
                  </span>
                </li>
              );
            })}
          </ol>
        ) : (
          <p className="muted">Zatím žádné události.</p>
        )}
      </Section>
    </div>
  );
}

// ---------- Hardware ----------

function Hardware({ device, now }: { device: FleetDevice; now: number }) {
  const report = device.report;
  const hw = report?.hardware;
  const battery = hw?.battery ?? null;
  const facts: [string, ReactNode][] = report
    ? [
        ["Model", report.model],
        ["Identifikátor modelu", hw?.modelId || "—"],
        ["Čip", hw?.chip ?? "—"],
        [
          "Jádra",
          hw
            ? hw.performanceCores !== null && hw.efficiencyCores !== null
              ? `${hw.cores} (${hw.performanceCores} výkonných, ${hw.efficiencyCores} úsporných)`
              : String(hw.cores)
            : "—",
        ],
        ["Paměť", formatRam(hw ? hw.memory : report.memory.total)],
        ["Úložiště", report.disk ? `${formatBytes(report.disk.total)}, volno ${formatBytes(report.disk.free)}` : "—"],
        ["Sériové číslo", hw?.serial ? <code key="s">{hw.serial}</code> : "—"],
        ["macOS", report.osVersion],
        ["AntiShield", report.appVersion],
        ["Ve firmě od", formatDate(device.joinedAtMs)],
        ["Otisk klíče Macu", <code key="f">{groupFingerprint(device.fingerprint)}</code>],
        ["Poslední zpráva", `${formatDateTime(report.createdAtMs)} (${agoText(report.createdAtMs, now)})`],
      ]
    : [];
  const r = 46;
  const circle = 2 * Math.PI * r;
  return (
    <div className="device-grid">
      <Section title="Počítač" className={battery ? undefined : "span-2"}>
        {!hw && !shares(device.policy, "hardware") ? <NotShared what="Čip, sériové číslo a baterii" /> : null}
        <dl className="spec-grid">
          {facts.map(([label, value]) => (
            <div key={label}>
              <dt>{label}</dt>
              <dd>{value}</dd>
            </div>
          ))}
        </dl>
      </Section>
      {battery ? (
        <Section title="Baterie">
          <div className={`battery-card tone-${battery.service ? "caution" : "good"}`}>
            <figure className="health-ring is-small" aria-label={`Kapacita baterie ${battery.healthPct ?? "?"} %`}>
              <svg viewBox="0 0 112 112" aria-hidden="true">
                <circle className="health-track" cx="56" cy="56" r={r} />
                <circle
                  className="health-fill"
                  cx="56"
                  cy="56"
                  r={r}
                  strokeDasharray={`${((battery.healthPct ?? 0) / 100) * circle} ${circle}`}
                />
              </svg>
              <div className="health-center">
                <span className="health-score">{battery.healthPct ?? "?"}</span>
                <span className="health-of">% kapacity</span>
              </div>
            </figure>
            <dl className="fleet-facts">
              <div>
                <dt>Stav</dt>
                <dd>{battery.service ? "Potřebuje servis" : "Normální"}</dd>
              </div>
              <div>
                <dt>Cykly</dt>
                <dd>{battery.cycles}</dd>
              </div>
              <div>
                <dt>Nabití</dt>
                <dd>
                  {battery.chargePct !== null ? `${battery.chargePct} %` : "—"}
                  {battery.charging ? <span className="muted"> · nabíjí se</span> : null}
                </dd>
              </div>
              <div>
                <dt>Napájení</dt>
                <dd>{battery.onPower ? "Ze sítě" : "Z baterie"}</dd>
              </div>
            </dl>
          </div>
        </Section>
      ) : null}
    </div>
  );
}

// ---------- Historie ----------

function History({ device }: { device: FleetDevice }) {
  const apps = new Map((device.report?.performance?.apps ?? []).map((a) => [a.bundleId ?? a.name, a.name]));
  return (
    <div className="device-grid">
      <Section title="Zásahy na dálku" className="span-2" aside={<span className="muted">{device.commands.length}</span>}>
        {device.commands.length ? (
          <ol className="fleet-history is-wide">
            {device.commands.map((c) => {
              const s = commandStatus(c);
              const extra =
                c.kind === "cleanup" && c.categories.length
                  ? categoryList(c.categories)
                  : c.kind === "quitApps"
                    ? c.targets.map((t) => apps.get(t) ?? t).join(", ")
                    : c.kind === "deleteQuarantine"
                      ? formatCount(c.targets.length, "položka", "položky", "položek")
                      : c.note && c.kind !== "update"
                        ? c.note
                        : "";
              return (
                <li key={c.id} className={`tone-${s.tone}`}>
                  <span className="fleet-history-icon" aria-hidden="true">
                    <Icon name={KIND_ICON[c.kind]} size={16} />
                  </span>
                  <span className="fleet-history-text">
                    <strong>{commandTitle(c, device.policy)}</strong>
                    <span className="muted">
                      {formatDateTime(c.sentAtMs)}
                      {extra ? ` · ${extra}` : ""}
                      {c.error ? ` · ${c.error}` : ""}
                    </span>
                  </span>
                  <span className="fleet-history-state">
                    {s.tone === "busy" ? <span className="spinner" aria-hidden="true" /> : null}
                    {s.text}
                  </span>
                </li>
              );
            })}
          </ol>
        ) : (
          <p className="muted">Zatím žádný zásah.</p>
        )}
      </Section>
    </div>
  );
}

function RemoveFooter({ device, onRemove }: { device: FleetDevice; onRemove: () => Promise<void> }) {
  const [confirm, setConfirm] = useState(false);
  return (
    <footer className="device-foot">
      <span className="muted">
        Otisk Macu <code>{groupFingerprint(device.fingerprint)}</code>
        {device.report ? ` · ${device.report.model}` : ""}
      </span>
      {confirm ? (
        <div className="actions">
          <span className="muted">Mac dostane podepsaný pokyn ke zrušení správy.</span>
          <button type="button" className="btn-danger" onClick={() => void onRemove()}>
            Odebrat
          </button>
          <button type="button" className="btn-link" onClick={() => setConfirm(false)}>
            Ponechat
          </button>
        </div>
      ) : (
        <button type="button" className="btn-link" onClick={() => setConfirm(true)}>
          Odebrat z firmy…
        </button>
      )}
    </footer>
  );
}

