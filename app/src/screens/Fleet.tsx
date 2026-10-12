import { useEffect, useMemo, useState } from "react";
import { FleetMap, type FleetNode } from "../components/FleetMap";
import { Gauge } from "../components/Gauge";
import { Icon, type IconName } from "../components/Icon";
import { Sheet } from "../components/Sheet";
import { api, asError } from "../lib/api";
import { CATEGORIES, CATEGORY_ORDER, PRESSURE_TEXT, diskTone, memoryTone, uptimeText, uptimeTone } from "../lib/care";
import {
  POLICY_TEXT,
  activeThreats,
  agoText,
  categoriesWith,
  categoryList,
  commandInProgress,
  commandStatus,
  commandTitle,
  connectionText,
  deviceIssues,
  deviceTone,
  fleetHeadline,
  fleetTotals,
  groupFingerprint,
  initials,
  isOnline,
  policyRule,
  reclaimable,
  shortName,
  type FleetTone,
} from "../lib/fleet";
import { capitalize, describeError, displayPath, formatBytes, formatCount, formatDateTime } from "../lib/format";
import { SEVERITY_LABELS } from "../lib/story";
import type {
  CleanCategory,
  FleetAdmin,
  FleetCommand,
  FleetCommandKind,
  FleetDevice,
  FleetInvite,
} from "../lib/types";
import { useCountUp } from "../lib/useCountUp";

const LATEST = __APP_VERSION__;

const KIND_ICON: Record<FleetCommandKind, IconName> = { cleanup: "sparkle", scan: "search", isolate: "box" };

function Bytes({ value }: { value: number }) {
  return <>{formatBytes(useCountUp(value, 1100))}</>;
}

/** Krátký stav pro mapu (pod jménem Macu). */
function mapSub(device: FleetDevice, now: number): string {
  if (device.left) return "odpojený";
  const command = device.commands[0];
  if (command && commandInProgress(command)) {
    switch (command.state) {
      case "queued":
        return "příkaz čeká";
      case "awaitingConsent":
        return "čeká na souhlas";
      case "delivered":
        return "převzal příkaz";
      default:
        return command.kind === "cleanup" ? "uklízí…" : command.kind === "scan" ? "kontroluje…" : "izoluje…";
    }
  }
  if (command?.state === "done" && command.kind === "cleanup" && now - command.updatedAtMs < 10 * 60_000) {
    return `uvolněno ${formatBytes(command.freedBytes + command.trashedBytes)}`;
  }
  if (!isOnline(device, now)) return device.lastSeenMs ? `offline ${agoText(device.lastSeenMs, now).replace("před ", "")}` : "nepřipojený";
  const threats = activeThreats(device.report);
  if (threats) return formatCount(threats, "hrozba", "hrozby", "hrozeb");
  const disk = device.report?.disk;
  return disk ? `${formatBytes(disk.free)} volno` : "online";
}

interface Batch {
  kind: FleetCommandKind;
  ids: string[];
  sentAtMs: number;
}

function batchProgress(fleet: FleetAdmin, batch: Batch) {
  const commands = fleet.devices
    .filter((d) => batch.ids.includes(d.id))
    .map((d) => d.commands.find((c) => c.kind === batch.kind && c.sentAtMs >= batch.sentAtMs))
    .filter((c): c is FleetCommand => c !== undefined);
  const finished = commands.filter((c) => !commandInProgress(c));
  return {
    total: batch.ids.length,
    finished: finished.length,
    queued: commands.filter((c) => c.state === "queued").length,
    bytes: commands.reduce((sum, c) => sum + c.freedBytes + c.trashedBytes, 0),
    files: commands.reduce((sum, c) => sum + c.files, 0),
    threats: commands.reduce((sum, c) => sum + c.threats, 0),
    succeeded: commands.filter((c) => c.state === "done").length,
  };
}

export function Fleet({
  fleet,
  onUpdate,
  still,
}: {
  fleet: FleetAdmin;
  onUpdate: (next: FleetAdmin) => void;
  still: boolean;
}) {
  const [focus, setFocus] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
  const [inviting, setInviting] = useState<FleetInvite | "new" | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [batch, setBatch] = useState<Batch | null>(null);
  const [now, setNow] = useState(() => Date.now());

  // Časy („před 3 min“, online) se obnovují i bez nových dat.
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 15_000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => setNow(Date.now()), [fleet]);

  const totals = fleetTotals(fleet.devices, fleet.policy, LATEST, now);
  const order = { alert: 0, caution: 1, good: 2 } as const;
  const devices = useMemo(
    () =>
      [...fleet.devices].sort(
        (a, b) =>
          Number(a.left) - Number(b.left) ||
          order[deviceTone(a, LATEST, now)] - order[deviceTone(b, LATEST, now)] ||
          a.name.localeCompare(b.name, "cs"),
      ),
    [fleet.devices, now],
  );
  const active = devices.filter((d) => !d.left);
  const offline = active.filter((d) => !isOnline(d, now)).length;
  const nodes: FleetNode[] = active.map((d) => {
    const command = d.commands[0];
    return {
      id: d.id,
      label: shortName(d.name),
      sub: mapSub(d, now),
      tone: deviceTone(d, LATEST, now),
      threat: activeThreats(d.report) > 0,
      online: isOnline(d, now),
      diskUsed: d.report?.disk && d.report.disk.total > 0 ? 1 - d.report.disk.free / d.report.disk.total : null,
      command: command
        ? { id: command.id, kind: command.kind, state: command.state, bytes: command.freedBytes + command.trashedBytes }
        : null,
    };
  });

  const send = async (ids: string[], kind: FleetCommandKind, categories: CleanCategory[], asBatch = false) => {
    if (!ids.length) return;
    setError(null);
    setBusy(true);
    try {
      const sentAtMs = Date.now();
      onUpdate(await api.fleetCommand(ids, kind, categories));
      if (asBatch) setBatch({ kind, ids, sentAtMs: sentAtMs - 1000 });
    } catch (e) {
      setError(describeError(asError(e)));
    } finally {
      setBusy(false);
    }
  };

  const cleanAll = () =>
    void send(
      active.filter((d) => !commandInProgress(d.commands[0])).map((d) => d.id),
      "cleanup",
      fleet.policy.auto,
      true,
    );
  const scanAll = () =>
    void send(
      active.filter((d) => !commandInProgress(d.commands[0])).map((d) => d.id),
      "scan",
      [],
      true,
    );

  const progress = batch ? batchProgress(fleet, batch) : null;
  const running = progress !== null && progress.finished + progress.queued < progress.total;
  const reachable = progress ? progress.total - progress.queued : 0;
  const open = fleet.devices.find((d) => d.id === openId) ?? null;

  return (
    <div className="screen fleet">
      <div>
        <h1>Firemní Macy</h1>
        <p className="lede">
          Stav ochrany a údržba firemních počítačů na dálku. Příkazy podepisuje jen tento Mac a zprávy z firemních
          Maců jsou šifrované jen pro vás.
        </p>
      </div>
      {error ? (
        <p className="notice tone-alert" role="alert">
          {error}
        </p>
      ) : null}

      <section className={`panel fleet-panel tone-${totals.tone}`} aria-labelledby="fleet-title">
        <div className="fleet-stage">
          <FleetMap
            nodes={nodes}
            focus={focus}
            still={still}
            onFocus={setFocus}
            onSelect={setOpenId}
            coreLabel="Tento Mac"
            coreSub="správce"
          />
        </div>
        <div className="fleet-side" aria-live="polite">
          <p className="fleet-eyebrow">
            <Icon name="building" size={16} />
            {fleet.fleetName} · {formatCount(totals.devices, "Mac", "Macy", "Maců")}
          </p>

          {progress && batch ? (
            <>
              <p className={`care-figure${running ? "" : " is-done"}`}>
                <span className="care-number">
                  {batch.kind === "cleanup" ? <Bytes value={progress.bytes} /> : `${progress.finished} z ${reachable}`}
                </span>
                <span className="care-caption" id="fleet-title">
                  {batch.kind === "cleanup"
                    ? running
                      ? `uvolněno, hotovo ${progress.finished} z ${reachable}`
                      : `uvolněno na ${formatCount(progress.succeeded, "Macu", "Macích", "Macích")}`
                    : running
                      ? "Macy kontrolují…"
                      : progress.threats
                        ? `zkontrolováno, ${formatCount(progress.threats, "nález", "nálezy", "nálezů")}`
                        : "zkontrolováno, bez nálezu"}
                </span>
              </p>
              <ul className="care-result">
                {progress.queued ? (
                  <li>
                    <Icon name="clock" />
                    {formatCount(progress.queued, "Mac je", "Macy jsou", "Maců je")} offline, příkaz počká, až se
                    připojí.
                  </li>
                ) : null}
                {!running && batch.kind === "scan" ? (
                  <li>
                    <Icon name="check" /> {formatCount(progress.files, "soubor", "soubory", "souborů")} zkontrolováno
                  </li>
                ) : null}
              </ul>
              <div className="actions">
                <button type="button" className="btn-secondary" disabled={running} onClick={() => setBatch(null)}>
                  {running ? "Probíhá…" : "Hotovo"}
                </button>
              </div>
            </>
          ) : (
            <>
              <h2 id="fleet-title" className={`care-title fleet-headline tone-${totals.tone}`}>
                {fleetHeadline(totals)}
              </h2>
              <dl className="fleet-stats">
                <div>
                  <dt>Online</dt>
                  <dd>
                    {totals.online} <small>z {totals.devices}</small>
                  </dd>
                </div>
                <div>
                  <dt>Hlídání běží</dt>
                  <dd>
                    {totals.watched} <small>z {totals.devices}</small>
                  </dd>
                </div>
                <div className={totals.threats ? "tone-alert" : undefined}>
                  <dt>Hrozby</dt>
                  <dd>{totals.threats}</dd>
                </div>
                <div>
                  <dt>Lze uvolnit hned</dt>
                  <dd>{formatBytes(totals.autoBytes)}</dd>
                </div>
              </dl>
              <div className="actions">
                <button
                  type="button"
                  className="care-cta"
                  disabled={busy || totals.devices === 0 || totals.autoBytes === 0}
                  onClick={cleanAll}
                >
                  <Icon name="sparkle" />
                  Vyčistit všechny
                </button>
                <button type="button" className="btn-secondary" disabled={busy || totals.devices === 0} onClick={scanAll}>
                  Zkontrolovat všechny
                </button>
              </div>
              <p className="care-note">
                Uklidí {categoryList(fleet.policy.auto)}. {capitalize(categoryList(fleet.policy.consent))} jen se
                souhlasem uživatele, velké soubory a Koš nikdy.
                {offline ? ` ${formatCount(offline, "Mac je", "Macy jsou", "Maců je")} offline, příkaz počká, až se připojí.` : ""}
              </p>
            </>
          )}
        </div>
        <p className="fleet-trust">
          <Icon name="lock" size={15} />
          <span>
            Podepsáno klíčem tohoto Macu <code>{groupFingerprint(fleet.fingerprint)}</code>. Server je jen schránka,
            obsah zpráv nevidí.
          </span>
          <span className={`fleet-relay${fleet.relay.reachable ? " is-ok" : ""}`}>
            <span className="dot" aria-hidden="true" />
            {fleet.relay.reachable
              ? `Schránka dostupná${fleet.relay.checkedAtMs ? `, ${agoText(fleet.relay.checkedAtMs, now)}` : ""}`
              : "Schránka teď není dostupná"}
          </span>
        </p>
      </section>

      <section className="panel fleet-list-panel" aria-labelledby="fleet-list-title">
        <div className="panel-head">
          <h2 id="fleet-list-title">Počítače</h2>
          <button type="button" className="btn-secondary btn-small" onClick={() => setInviting("new")}>
            <Icon name="plus" size={16} />
            Přidat Mac
          </button>
        </div>
        {devices.length || fleet.invites.length ? (
          <ul className="fleet-list" onMouseLeave={() => setFocus(null)}>
            {devices.map((device) => (
              <DeviceRow
                key={device.id}
                device={device}
                fleet={fleet}
                now={now}
                focused={focus === device.id}
                busy={busy}
                onFocus={() => setFocus(device.id)}
                onOpen={() => setOpenId(device.id)}
                onClean={() => void send([device.id], "cleanup", categoriesWith(device.report, fleet.policy, "auto"))}
              />
            ))}
            {fleet.invites.map((invite) => (
              <li key={invite.id} className="fleet-row is-invite">
                <span className="fleet-avatar" aria-hidden="true">
                  {initials(invite.name)}
                </span>
                <span className="fleet-row-main">
                  <span className="fleet-row-name">{invite.name}</span>
                  <span className="fleet-row-meta">Pozvaný, čeká na připojení</span>
                </span>
                <span className="fleet-row-status muted">
                  {invite.expiresAtMs - now < 86_400_000
                    ? "Kód platí méně než den"
                    : `Kód platí ještě ${formatCount(Math.floor((invite.expiresAtMs - now) / 86_400_000), "den", "dny", "dní")}`}
                </span>
                <span />
                <span />
                <span className="fleet-row-action">
                  <button type="button" className="btn-link" onClick={() => setInviting(invite)}>
                    Zobrazit kód
                  </button>
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">
            Zatím tu není žádný Mac. Přidejte první: vytvoříte kód, který na firemním Macu vložíte do AntiShieldu.
          </p>
        )}
      </section>

      {open ? (
        <DeviceSheet
          device={open}
          fleet={fleet}
          now={now}
          busy={busy}
          onClose={() => setOpenId(null)}
          onSend={(kind, categories) => void send([open.id], kind, categories)}
          onRemove={async () => {
            try {
              onUpdate(await api.fleetRemoveDevice(open.id));
              setOpenId(null);
            } catch (e) {
              setError(describeError(asError(e)));
            }
          }}
        />
      ) : null}
      {inviting ? (
        <InviteDialog
          fleet={fleet}
          existing={inviting === "new" ? null : inviting}
          onClose={() => setInviting(null)}
          onCreated={(next) => onUpdate(next)}
        />
      ) : null}
    </div>
  );
}

function DeviceRow({
  device,
  fleet,
  now,
  focused,
  busy,
  onFocus,
  onOpen,
  onClean,
}: {
  device: FleetDevice;
  fleet: FleetAdmin;
  now: number;
  focused: boolean;
  busy: boolean;
  onFocus: () => void;
  onOpen: () => void;
  onClean: () => void;
}) {
  const report = device.report;
  const tone = deviceTone(device, LATEST, now);
  const issue = deviceIssues(device, LATEST, now)[0];
  const online = isOnline(device, now);
  const command = device.commands[0];
  const status = command ? commandStatus(command) : null;
  const recent = command && (commandInProgress(command) || now - command.updatedAtMs < 10 * 60_000);
  const auto = reclaimable(report, fleet.policy, "auto");
  const disk = report?.disk ?? null;
  return (
    <li
      className={`fleet-row tone-${tone}${focused ? " is-focus" : ""}${device.left ? " is-left" : ""}`}
      onMouseEnter={onFocus}
    >
      <span className={`fleet-avatar tone-${tone}${online ? " is-online" : ""}`} aria-hidden="true">
        {initials(device.name)}
      </span>
      <button type="button" className="fleet-row-main" onClick={onOpen} onFocus={onFocus}>
        <span className="fleet-row-name">{device.name}</span>
        <span className="fleet-row-meta">
          {report ? `${report.model} · ${report.osVersion}` : "Zatím bez zprávy"}
        </span>
      </button>
      <span className="fleet-row-status">
        <span className={`fleet-chip tone-${tone}`}>
          <span className="dot" aria-hidden="true" />
          {issue ? issue.text : "V pořádku"}
        </span>
        <span className={`fleet-row-conn${online ? " is-online" : ""}`}>{connectionText(device, now)}</span>
      </span>
      <span className="fleet-row-disk">
        {disk ? (
          <>
            <span className={`mini-bar tone-${diskTone(disk)}`} aria-hidden="true">
              <span style={{ transform: `scaleX(${disk.total > 0 ? 1 - disk.free / disk.total : 0})` }} />
            </span>
            <span>{formatBytes(disk.free)} volno</span>
          </>
        ) : null}
      </span>
      <span className="fleet-row-clean">
        {auto > 0 ? (
          <>
            <strong>{formatBytes(auto)}</strong>
            <span>lze uvolnit</span>
          </>
        ) : null}
      </span>
      <span className="fleet-row-action">
        {recent && status ? (
          <span className={`fleet-status tone-${status.tone}`}>
            {status.tone === "busy" ? <span className="spinner" aria-hidden="true" /> : <Icon name={status.tone === "good" ? "check" : "warning"} size={16} />}
            {status.text}
          </span>
        ) : !device.left && auto > 0 ? (
          <button type="button" className="btn-secondary btn-small" disabled={busy} onClick={onClean}>
            Vyčistit
          </button>
        ) : null}
        <button type="button" className="fleet-row-open" onClick={onOpen} aria-label={`Otevřít ${device.name}`}>
          <Icon name="chevron" size={18} />
        </button>
      </span>
    </li>
  );
}

function DeviceSheet({
  device,
  fleet,
  now,
  busy,
  onClose,
  onSend,
  onRemove,
}: {
  device: FleetDevice;
  fleet: FleetAdmin;
  now: number;
  busy: boolean;
  onClose: () => void;
  onSend: (kind: FleetCommandKind, categories: CleanCategory[]) => void;
  onRemove: () => Promise<void>;
}) {
  const [confirmRemove, setConfirmRemove] = useState(false);
  const report = device.report;
  const tone: FleetTone = deviceTone(device, LATEST, now);
  const issues = deviceIssues(device, LATEST, now);
  const online = isOnline(device, now);
  const inProgress = commandInProgress(device.commands[0]);
  const autoCats = categoriesWith(report, fleet.policy, "auto");
  const consentCats = categoriesWith(report, fleet.policy, "consent");
  const autoBytes = reclaimable(report, fleet.policy, "auto");
  const consentBytes = reclaimable(report, fleet.policy, "consent");
  const threats = report?.threats ?? [];
  const pendingThreats = activeThreats(report);
  const disk = report?.disk ?? null;

  return (
    <Sheet labelledBy="device-title" className={`fleet-sheet tone-${tone}`} onClose={onClose} closeLabel="Zavřít detail Macu">
      <header className="story-head">
        <span className={`story-badge fleet-badge tone-${tone}`}>
          <Icon name="laptop" size={16} /> Firemní Mac
        </span>
        <h2 id="device-title">{device.name}</h2>
        <p className="story-rule">
          {report ? `${report.model} · ${report.osVersion} · AntiShield ${report.appVersion}` : "Mac zatím neposlal svůj stav."}
        </p>
        <p className={`fleet-sheet-conn${online ? " is-online" : ""}`}>
          <span className="dot" aria-hidden="true" />
          {connectionText(device, now)}
          {report ? ` · stav ověřený podpisem Macu ${agoText(report.createdAtMs, now)}` : ""}
        </p>
        {issues.length ? (
          <ul className="fleet-issues">
            {issues.map((i) => (
              <li key={i.text} className={`fleet-chip tone-${i.tone}`}>
                <span className="dot" aria-hidden="true" />
                {i.text}
              </li>
            ))}
          </ul>
        ) : null}
      </header>

      {report ? (
        <>
          <section className="sheet-section" aria-labelledby="dev-state">
            <h3 id="dev-state">Stav</h3>
            <div className="gauges fleet-gauges is-still">
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
                tone={memoryTone({ ...report.memory, swapUsed: 0 })}
                primary={`${Math.round((report.memory.used / Math.max(1, report.memory.total)) * 100)} %`}
                secondary={report.memory.pressure ? PRESSURE_TEXT[report.memory.pressure] : ""}
              />
              <figure className={`uptime tone-${uptimeTone(report.uptimeSecs)}`}>
                <Icon name="clock" />
                <span className="uptime-value">{uptimeText(report.uptimeSecs)}</span>
                <figcaption>bez restartu</figcaption>
              </figure>
            </div>
          </section>

          <section className="sheet-section" aria-labelledby="dev-protection">
            <h3 id="dev-protection">Ochrana</h3>
            <dl className="fleet-facts">
              <div>
                <dt>Hlídání</dt>
                <dd>
                  {report.protection === "monitored" || report.protection === "protected"
                    ? "Běží"
                    : report.protection === "manualScanOnly"
                      ? "Omezené, jen ruční kontrola"
                      : "Nefunguje"}
                  {report.protectionNote ? <span className="muted"> · {report.protectionNote}</span> : null}
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
                        · {report.lastScan.kind === "full" ? "úplná" : report.lastScan.kind === "quick" ? "rychlá" : "vlastní"},{" "}
                        {formatCount(report.lastScan.files, "soubor", "soubory", "souborů")},{" "}
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
            ) : null}
            <div className="actions">
              {pendingThreats ? (
                <button type="button" className="btn-danger" disabled={busy || inProgress || device.left} onClick={() => onSend("isolate", [])}>
                  Izolovat {formatCount(pendingThreats, "hrozbu", "hrozby", "hrozeb")}
                </button>
              ) : null}
              <button type="button" className="btn-secondary" disabled={busy || inProgress || device.left} onClick={() => onSend("scan", [])}>
                Zkontrolovat na dálku
              </button>
            </div>
          </section>

          <section className="sheet-section" aria-labelledby="dev-clean">
            <h3 id="dev-clean">
              Úklid
              {report.cleanup ? <span className="muted"> · změřeno {agoText(report.cleanup.measuredAtMs, now)}</span> : null}
            </h3>
            {report.cleanup ? (
              <ul className="care-legend fleet-legend">
                {CATEGORY_ORDER.map((cat) => {
                  const bytes = report.cleanup?.categories.find((c) => c.category === cat)?.bytes ?? 0;
                  if (bytes <= 0) return null;
                  const rule = policyRule(fleet.policy, cat);
                  return (
                    <li key={cat} className={`is-${rule}`} style={{ "--cat": CATEGORIES[cat].rgb } as React.CSSProperties}>
                      <span className="legend-dot" aria-hidden="true" />
                      <span className="legend-text">
                        <span className="legend-label">{CATEGORIES[cat].label}</span>
                      </span>
                      <span className={`policy-badge is-${rule}`}>{POLICY_TEXT[rule]}</span>
                      <span className="legend-size">{formatBytes(bytes)}</span>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p className="muted">Mac zatím nezměřil, kolik jde uklidit.</p>
            )}
            <div className="actions">
              <button
                type="button"
                className="care-cta btn-cta-small"
                disabled={busy || inProgress || device.left || autoBytes === 0}
                onClick={() => onSend("cleanup", autoCats)}
              >
                <Icon name="sparkle" />
                Uklidit na dálku {autoBytes > 0 ? formatBytes(autoBytes) : ""}
              </button>
              {consentBytes > 0 ? (
                <button
                  type="button"
                  className="btn-secondary"
                  disabled={busy || inProgress || device.left}
                  onClick={() => onSend("cleanup", consentCats)}
                >
                  Požádat o úklid {formatBytes(consentBytes)}
                </button>
              ) : null}
            </div>
            <p className="care-note">
              Mac si vše před úklidem znovu najde sám. Mezipaměti běžících aplikací a nedávno použité soubory vynechá.
              Velké soubory a Koš patří uživateli, ty na dálku nejdou.
            </p>
          </section>
        </>
      ) : null}

      {device.commands.length ? (
        <section className="sheet-section" aria-labelledby="dev-history">
          <h3 id="dev-history">Zásahy na dálku</h3>
          <ol className="fleet-history">
            {device.commands.map((c) => {
              const s = commandStatus(c);
              return (
                <li key={c.id} className={`tone-${s.tone}`}>
                  <span className="fleet-history-icon" aria-hidden="true">
                    <Icon name={KIND_ICON[c.kind]} size={16} />
                  </span>
                  <span className="fleet-history-text">
                    <strong>{commandTitle(c, fleet.policy)}</strong>
                    <span className="muted">
                      {formatDateTime(c.sentAtMs)}
                      {c.kind === "cleanup" && c.categories.length ? ` · ${categoryList(c.categories)}` : ""}
                    </span>
                  </span>
                  <span className="fleet-history-state">{s.text}</span>
                </li>
              );
            })}
          </ol>
        </section>
      ) : null}

      <footer className="story-foot fleet-sheet-foot">
        <span className="muted">
          Otisk Macu <code>{groupFingerprint(device.fingerprint)}</code>
        </span>
        {confirmRemove ? (
          <div className="actions">
            <span className="muted">Mac dostane podepsaný pokyn ke zrušení správy.</span>
            <button type="button" className="btn-danger" onClick={() => void onRemove()}>
              Odebrat
            </button>
            <button type="button" className="btn-link" onClick={() => setConfirmRemove(false)}>
              Ponechat
            </button>
          </div>
        ) : (
          <button type="button" className="btn-link" onClick={() => setConfirmRemove(true)}>
            Odebrat z firmy…
          </button>
        )}
      </footer>
    </Sheet>
  );
}

function InviteDialog({
  fleet,
  existing,
  onClose,
  onCreated,
}: {
  fleet: FleetAdmin;
  existing: FleetInvite | null;
  onClose: () => void;
  onCreated: (next: FleetAdmin) => void;
}) {
  const [name, setName] = useState("");
  const [invite, setInvite] = useState<FleetInvite | null>(existing);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      const created = await api.fleetInvite(name.trim());
      setInvite(created);
      onCreated({ ...fleet, invites: [...fleet.invites, created] });
    } catch (e) {
      setError(describeError(asError(e)));
    } finally {
      setBusy(false);
    }
  };

  const copy = async () => {
    if (!invite) return;
    try {
      await navigator.clipboard.writeText(invite.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  return (
    <Sheet labelledBy="invite-title" className="invite-sheet" onClose={onClose} closeLabel="Zavřít">
      <header className="story-head">
        <span className="story-badge fleet-badge tone-good">
          <Icon name="plus" size={16} /> Nový firemní Mac
        </span>
        <h2 id="invite-title">{invite ? `Kód pro ${invite.name}` : "Přidat firemní Mac"}</h2>
      </header>
      {invite ? (
        <>
          <div className="invite-code">
            <code>{invite.code}</code>
            <button type="button" className="btn-secondary btn-small" onClick={() => void copy()}>
              <Icon name={copied ? "check" : "copy"} size={16} />
              {copied ? "Zkopírováno" : "Kopírovat"}
            </button>
          </div>
          <ol className="invite-steps">
            <li>Na firemním Macu otevřete AntiShield, Nastavení, Firemní správa.</li>
            <li>Vložte kód. Mac ukáže, co uvidíte a co smíte na dálku, a uživatel připojení potvrdí.</li>
            <li>Mac se tady objeví do minuty.</li>
          </ol>
          <p className="care-note">
            Kód platí do {formatDateTime(invite.expiresAtMs)} a jde použít jen jednou. Uživatel uvidí otisk vašeho klíče{" "}
            <code>{groupFingerprint(fleet.fingerprint)}</code>. Ověřte si ho spolu, třeba po telefonu.
          </p>
          <div className="actions">
            <button type="button" className="care-cta btn-cta-small" onClick={onClose}>
              Hotovo
            </button>
          </div>
        </>
      ) : (
        <>
          <label className="field">
            <span>Komu Mac patří</span>
            <input
              type="text"
              value={name}
              maxLength={60}
              placeholder="Jméno a příjmení"
              onChange={(e) => setName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && name.trim() && void create()}
            />
          </label>
          <p className="care-note">
            Jméno uvidíte jen vy, v seznamu a na mapě. Kód pro připojení platí 7 dní a jen pro jeden Mac.
          </p>
          {error ? <p className="notice tone-alert">{error}</p> : null}
          <div className="actions">
            <button type="button" className="care-cta btn-cta-small" disabled={busy || !name.trim()} onClick={() => void create()}>
              {busy ? "Vytvářím…" : "Vytvořit kód"}
            </button>
            <button type="button" className="btn-link" onClick={onClose}>
              Zrušit
            </button>
          </div>
        </>
      )}
    </Sheet>
  );
}
