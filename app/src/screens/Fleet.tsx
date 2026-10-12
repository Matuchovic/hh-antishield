import { useEffect, useMemo, useState } from "react";
import { FleetMap, type FleetNode } from "../components/FleetMap";
import { Icon } from "../components/Icon";
import { Sheet } from "../components/Sheet";
import { api, asError } from "../lib/api";
import { diskTone } from "../lib/care";
import {
  activeThreats,
  agoText,
  commandInProgress,
  commandStatus,
  connectionText,
  deepNowBytes,
  deviceIssues,
  deviceTone,
  fleetHeadline,
  fleetTotals,
  groupFingerprint,
  hasAction,
  initials,
  isOnline,
  shortName,
} from "../lib/fleet";
import { describeError, formatBytes, formatCount, formatDateTime } from "../lib/format";
import type {
  CleanCategory,
  FleetAdmin,
  FleetCommand,
  FleetCommandKind,
  FleetCommandOptions,
  FleetDevice,
  FleetInvite,
} from "../lib/types";
import { useCountUp } from "../lib/useCountUp";
import { FleetDevicePage } from "./FleetDevice";

const LATEST = __APP_VERSION__;

const BUSY_TEXT: Partial<Record<FleetCommandKind, string>> = {
  cleanup: "uklízí…",
  scan: "kontroluje…",
  isolate: "izoluje…",
  update: "aktualizuje…",
  deleteQuarantine: "maže karanténu…",
};

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
        return BUSY_TEXT[command.kind] ?? "pracuje…";
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

  const totals = fleetTotals(fleet.devices, LATEST, now);
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

  const send = async (
    ids: string[],
    kind: FleetCommandKind,
    categories: CleanCategory[],
    options?: FleetCommandOptions,
    asBatch = false,
  ) => {
    if (!ids.length) return;
    setError(null);
    setBusy(true);
    try {
      const sentAtMs = Date.now();
      onUpdate(await api.fleetCommand(ids, kind, categories, options));
      if (asBatch) setBatch({ kind, ids, sentAtMs: sentAtMs - 1000 });
    } catch (e) {
      setError(describeError(asError(e)));
    } finally {
      setBusy(false);
    }
  };

  // Macy s rozšířenou správou uklidí hloubkově, ostatní běžně.
  const cleanAll = async () => {
    const ready = active.filter((d) => !commandInProgress(d.commands[0]));
    const deep = ready.filter((d) => hasAction(d.policy, "deepClean"));
    const basic = ready.filter((d) => !hasAction(d.policy, "deepClean"));
    const sentAtMs = Date.now();
    if (deep.length) await send(deep.map((d) => d.id), "cleanup", fleet.policy.auto, { deep: true });
    if (basic.length) await send(basic.map((d) => d.id), "cleanup", fleet.policy.auto);
    setBatch({ kind: "cleanup", ids: ready.map((d) => d.id), sentAtMs: sentAtMs - 1000 });
  };
  const scanAll = () =>
    void send(
      active.filter((d) => !commandInProgress(d.commands[0])).map((d) => d.id),
      "scan",
      [],
      undefined,
      true,
    );

  const progress = batch ? batchProgress(fleet, batch) : null;
  const running = progress !== null && progress.finished + progress.queued < progress.total;
  const reachable = progress ? progress.total - progress.queued : 0;
  const open = fleet.devices.find((d) => d.id === openId) ?? null;

  if (open) {
    return (
      <FleetDevicePage
        device={open}
        fleet={fleet}
        now={now}
        busy={busy}
        latest={LATEST}
        onBack={() => setOpenId(null)}
        onSend={(kind, categories, options) => send([open.id], kind, categories, options)}
        onRemove={async () => {
          try {
            onUpdate(await api.fleetRemoveDevice(open.id));
            setOpenId(null);
          } catch (e) {
            setError(describeError(asError(e)));
          }
        }}
      />
    );
  }

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
                  onClick={() => void cleanAll()}
                >
                  <Icon name="sparkle" />
                  Vyčistit všechny
                </button>
                <button type="button" className="btn-secondary" disabled={busy || totals.devices === 0} onClick={scanAll}>
                  Zkontrolovat všechny
                </button>
              </div>
              <p className="care-note">
                Uklidí mezipaměti, protokoly a vývojářská data (s rozšířenou správou hloubkově). Instalátory, Koš
                a velké soubory jen se souhlasem uživatele, dokumenty a fotky nikdy.
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
                now={now}
                focused={focus === device.id}
                busy={busy}
                onFocus={() => setFocus(device.id)}
                onOpen={() => setOpenId(device.id)}
                onClean={() =>
                  void send(
                    [device.id],
                    "cleanup",
                    device.policy.auto,
                    hasAction(device.policy, "deepClean") ? { deep: true } : undefined,
                  )
                }
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
  now,
  focused,
  busy,
  onFocus,
  onOpen,
  onClean,
}: {
  device: FleetDevice;
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
  const auto = deepNowBytes(device);
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
