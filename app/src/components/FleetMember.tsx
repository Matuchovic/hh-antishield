import { useEffect, useState, type ReactNode } from "react";
import { api, asError } from "../lib/api";
import { CATEGORIES, uptimeText } from "../lib/care";
import { agoText, categoryList, groupFingerprint, hasAction, shares } from "../lib/fleet";
import { capitalize, describeError, displayPath, formatBytes, formatCount, formatDate, formatTime } from "../lib/format";
import type {
  CleanCategory,
  FleetApproval,
  FleetApprovalChoice,
  FleetApprovalDetails,
  FleetJoinPreview,
  FleetPolicy,
} from "../lib/types";
import type { Fleet } from "../lib/useFleet";
import { Icon } from "./Icon";
import { Sheet } from "./Sheet";

/** Položka seznamu zásad; nová proti dosavadním zásadám má značku. */
function Item({ fresh, children }: { fresh?: boolean; children: ReactNode }) {
  return (
    <li className={fresh ? "is-new" : undefined}>
      {children}
      {fresh ? <span className="new-badge">Nové</span> : null}
    </li>
  );
}

/** Co správce firmy uvidí a smí; stejný text při připojení, v Nastavení
 *  i v žádosti o rozšířenou správu (tam s vyznačením novinek proti `previous`). */
export function PolicyLists({ policy, previous }: { policy: FleetPolicy; previous?: FleetPolicy }) {
  const isNewShare = (s: Parameters<typeof shares>[1]) => previous !== undefined && !shares(previous, s);
  const isNewAction = (a: Parameters<typeof hasAction>[1]) => previous !== undefined && !hasAction(previous, a);
  const isNewConsent = (c: CleanCategory) =>
    previous !== undefined && !previous.consent.includes(c) && !previous.auto.includes(c);
  const consentPlain = policy.consent.filter((c) => c === "installers" || c === "leftovers");
  return (
    <div className="policy-lists">
      <section className="policy-col">
        <h4>
          <Icon name="search" size={16} /> Správce uvidí
        </h4>
        <ul>
          <Item>stav ochrany, pravidel a poslední kontroly</Item>
          <Item>nalezené hrozby: název a umístění souboru</Item>
          <Item>místo na disku, paměť a dobu od restartu</Item>
          <Item>kolik jde uklidit, jen velikosti bez názvů souborů</Item>
          {shares(policy, "hardware") ? <Item fresh={isNewShare("hardware")}>čip, paměť, sériové číslo a stav baterie</Item> : null}
          {shares(policy, "security") ? (
            <Item fresh={isNewShare("security")}>FileVault, firewall, SIP, Gatekeeper, čekající aktualizace macOS a zálohu</Item>
          ) : null}
          {shares(policy, "performance") ? (
            <Item fresh={isNewShare("performance")}>vytížení, nejnáročnější aplikace a položky po přihlášení (jen názvy)</Item>
          ) : null}
          {shares(policy, "threats") ? (
            <Item fresh={isNewShare("threats")}>karanténu (název, umístění, důvod) a události ochrany</Item>
          ) : null}
        </ul>
      </section>
      <section className="policy-col">
        <h4>
          <Icon name="sparkle" size={16} /> Smí na dálku
        </h4>
        <ul>
          <Item>
            spustit kontrolu{hasAction(policy, "fullScan") ? " (i úplnou)" : ""} a izolovat nalezené hrozby do karantény
          </Item>
          <Item fresh={isNewAction("deepClean")}>
            uklidit {categoryList(policy.auto)}
            {hasAction(policy, "deepClean") ? ", hloubkově i čerstvé mezipaměti aplikací, které neběží" : ""}
          </Item>
          {hasAction(policy, "quarantineDelete") ? (
            <Item fresh={isNewAction("quarantineDelete")}>smazat soubory z karantény</Item>
          ) : null}
          {hasAction(policy, "updates") ? (
            <Item fresh={isNewAction("updates")}>aktualizovat AntiShield a pravidla (jen podepsaná vydání)</Item>
          ) : null}
        </ul>
      </section>
      <section className="policy-col is-consent">
        <h4>
          <Icon name="check" size={16} /> Jen s vaším souhlasem
        </h4>
        <ul>
          {consentPlain.length ? (
            <Item>{capitalize(categoryList(consentPlain))}. Přesunou se do Koše, odkud je jde vrátit.</Item>
          ) : null}
          {policy.consent.includes("largeFiles") ? (
            <Item fresh={isNewConsent("largeFiles")}>velké staré soubory, které sami vyberete (do Koše)</Item>
          ) : null}
          {policy.consent.includes("trash") ? <Item fresh={isNewConsent("trash")}>vysypání Koše</Item> : null}
          {hasAction(policy, "deepClean") ? (
            <Item fresh={isNewAction("deepClean")}>zavření aplikací kvůli úklidu jejich mezipamětí</Item>
          ) : null}
          {hasAction(policy, "restart") ? <Item fresh={isNewAction("restart")}>restart (můžete ho odložit)</Item> : null}
          {hasAction(policy, "quitApps") ? (
            <Item fresh={isNewAction("quitApps")}>ukončení aplikací, které sami vyberete</Item>
          ) : null}
        </ul>
      </section>
      <section className="policy-col is-never">
        <h4>
          <Icon name="lock" size={16} /> Nikdy
        </h4>
        <ul>
          <li>vaše dokumenty, fotky, zprávy, hesla ani historie prohlížeče se z Macu neposílají</li>
          <li>ochranu ani nastavení systému na dálku nezmění</li>
          <li>nic bez oznámení: o každém zásahu víte</li>
        </ul>
      </section>
    </div>
  );
}

const KIND_TITLE: Record<FleetApproval["kind"], string> = {
  cleanup: "navrhuje úklid",
  restart: "žádá o restart",
  quitApps: "navrhuje ukončit aplikace",
  policy: "žádá o rozšířenou správu",
};

function approvalSummary(approval: FleetApproval): string {
  switch (approval.kind) {
    case "cleanup": {
      const parts: string[] = [];
      if (approval.categories.length) parts.push(capitalize(categoryList(approval.categories)));
      if (approval.apps.length) parts.push(`zavřít ${approval.apps.map((a) => a.name).join(", ")}`);
      return `${parts.join("; ")}, až ${formatBytes(approval.bytes)}. Sami vyberete, co uklidit.`;
    }
    case "restart":
      return "Uložte si rozdělanou práci. Restartovat můžete teď, nebo později.";
    case "quitApps":
      return `${approval.apps.map((a) => a.name).join(", ")}. Aplikace se zeptají na uložení práce.`;
    case "policy":
      return "Uvidíte přesně, co by správce navíc viděl a smí, a rozhodnete.";
  }
}

/** Minuty do zítřka 9:00 (odložení restartu „zítra ráno“). */
function minutesUntilTomorrow(now = new Date()): number {
  const tomorrow = new Date(now);
  tomorrow.setDate(now.getDate() + 1);
  tomorrow.setHours(9, 0, 0, 0);
  return Math.max(5, Math.min(24 * 60, Math.round((tomorrow.getTime() - now.getTime()) / 60_000)));
}

/** Žádosti správce, které čekají na souhlas uživatele (nahoře na každé obrazovce). */
export function FleetApprovals({ fleet }: { fleet: Fleet }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [open, setOpen] = useState<FleetApproval | null>(null);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(timer);
  }, []);
  const member = fleet.member;
  if (!member || !member.approvals.length) return null;
  const decide = async (approval: FleetApproval, approve: boolean, choice?: FleetApprovalChoice) => {
    setBusy(approval.id);
    try {
      fleet.setMember(await api.fleetApprove(approval.id, approve, choice));
      setOpen(null);
    } finally {
      setBusy(null);
    }
  };
  const current = open ? member.approvals.find((a) => a.id === open.id) ?? null : null;
  return (
    <>
      {member.approvals.map((approval) => {
        const snoozed = approval.snoozedUntilMs !== null && approval.snoozedUntilMs > now;
        return (
          <div key={approval.id} className={`fleet-approval kind-${approval.kind}${snoozed ? " is-snoozed" : ""}`} role="status">
            <span className="fleet-approval-icon" aria-hidden="true">
              <Icon
                name={approval.kind === "restart" ? "power" : approval.kind === "policy" ? "key" : approval.kind === "quitApps" ? "close" : "building"}
                size={20}
              />
            </span>
            <p>
              <strong>
                {member.adminName} {KIND_TITLE[approval.kind]}
              </strong>
              <span>
                {snoozed && approval.snoozedUntilMs
                  ? `Odloženo do ${formatTime(approval.snoozedUntilMs)}.`
                  : approvalSummary(approval)}
              </span>
            </p>
            <div className="actions">
              <button
                type="button"
                className="btn-secondary btn-small"
                disabled={busy !== null}
                onClick={() => setOpen(approval)}
              >
                {approval.kind === "restart" ? "Restartovat…" : approval.kind === "cleanup" ? "Vybrat a uklidit…" : "Zobrazit…"}
              </button>
              {approval.kind === "restart" && !snoozed ? (
                <button
                  type="button"
                  className="btn-link"
                  disabled={busy !== null}
                  onClick={() => void decide(approval, true, { snoozeMinutes: 60 })}
                >
                  Za hodinu
                </button>
              ) : null}
              <button type="button" className="btn-link" disabled={busy !== null} onClick={() => void decide(approval, false)}>
                {approval.kind === "policy" ? "Ne" : "Teď ne"}
              </button>
            </div>
          </div>
        );
      })}
      {current ? (
        <ApprovalDialog
          approval={current}
          adminName={member.adminName}
          policy={member.policy}
          busy={busy === current.id}
          onClose={() => setOpen(null)}
          onDecide={(approve, choice) => void decide(current, approve, choice)}
        />
      ) : null}
    </>
  );
}

function ApprovalDialog({
  approval,
  adminName,
  policy,
  busy,
  onClose,
  onDecide,
}: {
  approval: FleetApproval;
  adminName: string;
  policy: FleetPolicy;
  busy: boolean;
  onClose: () => void;
  onDecide: (approve: boolean, choice?: FleetApprovalChoice) => void;
}) {
  const [details, setDetails] = useState<FleetApprovalDetails | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [categories, setCategories] = useState<Set<CleanCategory>>(
    () => new Set(approval.categories.filter((c) => c !== "trash" && c !== "largeFiles")),
  );
  const [items, setItems] = useState<Set<string>>(new Set());
  const [apps, setApps] = useState<Set<string>>(() => new Set(approval.apps.map((a) => a.id)));
  useEffect(() => {
    if (approval.kind !== "cleanup" && approval.kind !== "restart") return;
    api
      .fleetApprovalDetails(approval.id)
      .then(setDetails)
      .catch((e) => setError(describeError(asError(e))));
  }, [approval.id, approval.kind]);
  const toggle = <T,>(set: (fn: (prev: Set<T>) => Set<T>) => void, value: T) =>
    set((prev) => {
      const next = new Set(prev);
      if (next.has(value)) next.delete(value);
      else next.add(value);
      return next;
    });

  const title =
    approval.kind === "cleanup"
      ? `${adminName} navrhuje úklid`
      : approval.kind === "restart"
        ? `${adminName} žádá o restart`
        : approval.kind === "quitApps"
          ? `${adminName} navrhuje ukončit aplikace`
          : `${adminName} žádá o rozšířenou správu`;

  let body: ReactNode = null;
  let actions: ReactNode = null;
  if (approval.kind === "cleanup") {
    const large = details?.categories.find((c) => c.category === "largeFiles");
    const chosenCategories = [...categories].filter((c) => c !== "largeFiles" || items.size > 0);
    const withLarge = items.size ? [...new Set([...chosenCategories, "largeFiles" as CleanCategory])] : chosenCategories;
    body = (
      <>
        <ul className="consent-list">
          {approval.categories
            .filter((c) => c !== "largeFiles")
            .map((c) => {
              const detail = details?.categories.find((d) => d.category === c);
              return (
                <li key={c}>
                  <label>
                    <input type="checkbox" checked={categories.has(c)} onChange={() => toggle(setCategories, c)} />
                    <span>
                      <strong>{c === "trash" ? "Vysypat Koš" : CATEGORIES[c].label}</strong>
                      <span className="muted">
                        {c === "trash"
                          ? `${detail ? formatCount(detail.files, "soubor", "soubory", "souborů") + ", " : ""}nevratné`
                          : "Přesune se do Koše, odkud to jde vrátit."}
                      </span>
                    </span>
                    <em>{detail ? formatBytes(detail.bytes) : "…"}</em>
                  </label>
                </li>
              );
            })}
          {approval.apps.map((app) => (
            <li key={app.id}>
              <label>
                <input type="checkbox" checked={apps.has(app.id)} onChange={() => toggle(setApps, app.id)} />
                <span>
                  <strong>Zavřít {app.name} a uklidit její mezipaměti</strong>
                  <span className="muted">Aplikace se zeptá na uložení práce. Pak ji můžete hned znovu otevřít.</span>
                </span>
                <em>{formatBytes(app.bytes)}</em>
              </label>
            </li>
          ))}
        </ul>
        {large && large.items.length ? (
          <div className="consent-files">
            <h3>Velké staré soubory: vyberte, které přesunout do Koše</h3>
            <p className="muted">Názvy souborů vidíte jen vy, správci se neposílají.</p>
            <ul>
              {large.items.map((item) => (
                <li key={item.id}>
                  <label>
                    <input type="checkbox" checked={items.has(item.id)} onChange={() => toggle(setItems, item.id)} />
                    <span>
                      <strong>{item.name}</strong>
                      <span className="muted item-path" title={displayPath(item.path)}>{`‎${displayPath(item.path)}‎`}</span>
                    </span>
                    <em>
                      {formatBytes(item.bytes)}
                      {item.modifiedMs ? <small>{formatDate(item.modifiedMs)}</small> : null}
                    </em>
                  </label>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {error ? <p className="notice tone-alert">{error}</p> : null}
      </>
    );
    const nothing = withLarge.length === 0 && apps.size === 0;
    actions = (
      <>
        <button
          type="button"
          className="care-cta btn-cta-small"
          disabled={busy || nothing}
          onClick={() => onDecide(true, { categories: withLarge, items: [...items], apps: [...apps] })}
        >
          {busy ? "Uklízím…" : "Uklidit vybrané"}
        </button>
        <button type="button" className="btn-link" disabled={busy} onClick={() => onDecide(false)}>
          Odmítnout
        </button>
      </>
    );
  } else if (approval.kind === "restart") {
    body = (
      <p className="story-summary">
        {details ? `Mac běží ${uptimeText(details.uptimeSecs)} bez restartu. ` : ""}Uložte si rozdělanou práci. Aplikace se
        před restartem zeptají na uložení; restart můžete i odložit.
      </p>
    );
    actions = (
      <>
        <button type="button" className="care-cta btn-cta-small" disabled={busy} onClick={() => onDecide(true)}>
          <Icon name="power" />
          Restartovat teď
        </button>
        <button type="button" className="btn-secondary" disabled={busy} onClick={() => onDecide(true, { snoozeMinutes: 60 })}>
          Za hodinu
        </button>
        <button
          type="button"
          className="btn-secondary"
          disabled={busy}
          onClick={() => onDecide(true, { snoozeMinutes: minutesUntilTomorrow() })}
        >
          Zítra ráno
        </button>
        <button type="button" className="btn-link" disabled={busy} onClick={() => onDecide(false)}>
          Odmítnout
        </button>
      </>
    );
  } else if (approval.kind === "quitApps") {
    body = (
      <ul className="consent-list">
        {approval.apps.map((app) => (
          <li key={app.id}>
            <label>
              <input type="checkbox" checked={apps.has(app.id)} onChange={() => toggle(setApps, app.id)} />
              <span>
                <strong>{app.name}</strong>
                <span className="muted">Zeptá se na uložení práce.</span>
              </span>
              <em>{formatBytes(app.bytes)} paměti</em>
            </label>
          </li>
        ))}
      </ul>
    );
    actions = (
      <>
        <button
          type="button"
          className="care-cta btn-cta-small"
          disabled={busy || apps.size === 0}
          onClick={() => onDecide(true, { apps: [...apps] })}
        >
          {busy ? "Ukončuji…" : "Ukončit vybrané"}
        </button>
        <button type="button" className="btn-link" disabled={busy} onClick={() => onDecide(false)}>
          Nechat běžet
        </button>
      </>
    );
  } else if (approval.policy) {
    body = (
      <>
        <p className="story-summary">
          Novinky jsou vyznačené. Dosavadní souhlas platí dál, pokud rozšíření odmítnete. Rozhodnutí můžete kdykoli změnit
          odpojením od firmy.
        </p>
        <PolicyLists policy={approval.policy} previous={policy} />
      </>
    );
    actions = (
      <>
        <button type="button" className="care-cta btn-cta-small" disabled={busy} onClick={() => onDecide(true)}>
          {busy ? "Ukládám…" : "Povolit rozšířenou správu"}
        </button>
        <button type="button" className="btn-link" disabled={busy} onClick={() => onDecide(false)}>
          Ponechat současný rozsah
        </button>
      </>
    );
  }

  return (
    <Sheet labelledBy="approval-title" className="join-sheet approval-sheet" onClose={onClose} closeLabel="Zavřít">
      <header className="story-head">
        <span className="story-badge fleet-badge tone-good">
          <Icon name="building" size={16} /> Firemní správa
        </span>
        <h2 id="approval-title">{title}</h2>
        <p className="muted">
          Žádost z {formatDate(approval.requestedAtMs)} platí do {formatDate(approval.expiresAtMs)} ({agoText(approval.requestedAtMs)}).
        </p>
      </header>
      {body}
      <div className="actions">{actions}</div>
    </Sheet>
  );
}

function JoinDialog({
  preview,
  code,
  onClose,
  onJoined,
}: {
  preview: FleetJoinPreview;
  code: string;
  onClose: () => void;
  onJoined: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const join = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.fleetJoin(code);
      onJoined();
    } catch (e) {
      setError(describeError(asError(e)));
      setBusy(false);
    }
  };
  return (
    <Sheet labelledBy="join-title" className="join-sheet" onClose={onClose} closeLabel="Zrušit připojení">
      <header className="story-head">
        <span className="story-badge fleet-badge tone-good">
          <Icon name="building" size={16} /> Firemní správa
        </span>
        <h2 id="join-title">Připojit tento Mac k firmě {preview.fleetName}?</h2>
        <p className="story-summary">
          Správce {preview.adminName} uvidí tento Mac jako „{preview.deviceName}“. O každém jeho zásahu dostanete
          oznámení.
        </p>
      </header>
      <PolicyLists policy={preview.policy} />
      <p className="join-fingerprint">
        <Icon name="key" size={18} />
        <span>
          Otisk klíče správce <code>{groupFingerprint(preview.adminFingerprint)}</code>
          <span className="muted">Ověřte si ho se správcem, třeba po telefonu. Jiný otisk znamená cizí kód.</span>
        </span>
      </p>
      {error ? <p className="notice tone-alert">{error}</p> : null}
      <div className="actions">
        <button type="button" className="care-cta btn-cta-small" disabled={busy} onClick={() => void join()}>
          {busy ? "Připojuji…" : "Připojit tento Mac"}
        </button>
        <button type="button" className="btn-link" onClick={onClose}>
          Zrušit
        </button>
      </div>
    </Sheet>
  );
}

function CreateDialog({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [activation, setActivation] = useState("");
  const [fleetName, setFleetName] = useState("");
  const [adminName, setAdminName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ready = activation.trim() && fleetName.trim() && adminName.trim();
  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.fleetCreate(activation.trim(), fleetName.trim(), adminName.trim());
      onCreated();
    } catch (e) {
      setError(describeError(asError(e)));
      setBusy(false);
    }
  };
  return (
    <Sheet labelledBy="create-title" className="join-sheet" onClose={onClose} closeLabel="Zavřít">
      <header className="story-head">
        <span className="story-badge fleet-badge tone-good">
          <Icon name="building" size={16} /> Firemní správa
        </span>
        <h2 id="create-title">Spravovat firemní Macy z tohoto Macu</h2>
        <p className="story-summary">
          Tento Mac vytvoří klíč správce. Podepisuje jím příkazy pro firemní Macy a jen on přečte jejich zprávy. Klíč
          tento Mac nikdy neopustí.
        </p>
      </header>
      <label className="field">
        <span>Aktivační kód (jednorázový, od provozovatele schránky)</span>
        <input
          type="text"
          className="code-input"
          value={activation}
          placeholder="HHA1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
          spellCheck={false}
          onChange={(e) => setActivation(e.target.value.toUpperCase())}
        />
      </label>
      <label className="field">
        <span>Název firmy</span>
        <input type="text" value={fleetName} maxLength={60} placeholder="H&H Security" onChange={(e) => setFleetName(e.target.value)} />
      </label>
      <label className="field">
        <span>Vaše jméno (uvidí ho uživatelé firemních Maců)</span>
        <input type="text" value={adminName} maxLength={60} placeholder="Jméno a příjmení" onChange={(e) => setAdminName(e.target.value)} />
      </label>
      {error ? <p className="notice tone-alert">{error}</p> : null}
      <div className="actions">
        <button type="button" className="care-cta btn-cta-small" disabled={busy || !ready} onClick={() => void create()}>
          {busy ? "Vytvářím…" : "Vytvořit"}
        </button>
        <button type="button" className="btn-link" onClick={onClose}>
          Zrušit
        </button>
      </div>
    </Sheet>
  );
}

/** Nastavení → Firemní správa: připojení k firmě, stav správy, odpojení. */
export function FleetSettingsPanel({ fleet, onOpenFleet }: { fleet: Fleet; onOpenFleet: () => void }) {
  const [code, setCode] = useState("");
  const [preview, setPreview] = useState<FleetJoinPreview | null>(null);
  const [creating, setCreating] = useState(false);
  const [confirmLeave, setConfirmLeave] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { admin, member } = fleet;

  const check = async () => {
    setBusy(true);
    setError(null);
    try {
      setPreview(await api.fleetJoinPreview(code.trim()));
    } catch (e) {
      setError(describeError(asError(e)));
    } finally {
      setBusy(false);
    }
  };
  const leave = async () => {
    setBusy(true);
    try {
      await api.fleetLeave();
      setConfirmLeave(false);
      await fleet.refresh();
    } catch (e) {
      setError(describeError(asError(e)));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel fleet-settings" aria-labelledby="s-fleet">
      <h2 id="s-fleet">Firemní správa</h2>

      {admin ? (
        <div className="fleet-member-head">
          <span className="fleet-avatar tone-good is-online" aria-hidden="true">
            <Icon name="building" size={18} />
          </span>
          <span>
            <strong>Tento Mac spravuje firemní Macy {admin.fleetName}</strong>
            <span className="muted">
              {formatCount(admin.devices.filter((d) => !d.left).length, "Mac", "Macy", "Maců")} · otisk klíče správce{" "}
              <code>{groupFingerprint(admin.fingerprint)}</code>
            </span>
          </span>
          <button type="button" className="btn-secondary btn-small" onClick={onOpenFleet}>
            Otevřít Firemní Macy
          </button>
        </div>
      ) : null}

      {member ? (
        <>
          <div className="fleet-member-head">
            <span
              className={`fleet-avatar ${member.problem ? "tone-caution" : "tone-good is-online"}`}
              aria-hidden="true"
            >
              <Icon name="building" size={18} />
            </span>
            <span>
              <strong>Tento Mac spravuje {member.fleetName}</strong>
              <span className="muted">
                Správce {member.adminName} · připojeno {formatDate(member.joinedAtMs)}
                {member.lastContactMs ? ` · spojení ${agoText(member.lastContactMs)}` : ""}
              </span>
            </span>
          </div>
          {member.problem ? (
            <p className="notice tone-caution" role="status">
              {describeError({ code: member.problem, message: "" })}
            </p>
          ) : null}
          <PolicyLists policy={member.policy} />
          <p className="care-note">
            Otisk klíče správce <code>{groupFingerprint(member.adminFingerprint)}</code>. Každý zásah na dálku uvidíte
            v oznámení a v Událostech. Příkaz bez platného podpisu správce Mac odmítne.
          </p>
          {confirmLeave ? (
            <div className="trash-row is-confirm">
              <p>Odpojit Mac od firmy? Správce uvidí, že jste ho odpojili, a přestane vidět jeho stav.</p>
              <div className="actions">
                <button type="button" className="btn-danger" disabled={busy} onClick={() => void leave()}>
                  Odpojit
                </button>
                <button type="button" className="btn-link" onClick={() => setConfirmLeave(false)}>
                  Ponechat
                </button>
              </div>
            </div>
          ) : (
            <div className="actions">
              <button type="button" className="btn-link" onClick={() => setConfirmLeave(true)}>
                Odpojit od firmy…
              </button>
            </div>
          )}
        </>
      ) : !admin ? (
        <>
          <p className="muted">
            Tento Mac nespravuje žádná firma. Pokud vám správce dal kód, vložte ho sem. Než se Mac připojí, uvidíte
            přesně, co správce uvidí a co smí.
          </p>
          <div className="join-row">
            <input
              type="text"
              className="code-input"
              value={code}
              placeholder="HHF1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
              spellCheck={false}
              autoCapitalize="characters"
              aria-label="Kód od správce"
              onChange={(e) => setCode(e.target.value.toUpperCase())}
              onKeyDown={(e) => e.key === "Enter" && code.trim() && void check()}
            />
            <button type="button" className="btn-secondary" disabled={busy || !code.trim()} onClick={() => void check()}>
              {busy ? "Ověřuji…" : "Pokračovat"}
            </button>
          </div>
          <p className="care-note">
            Spravujete firemní Macy vy?{" "}
            <button type="button" className="btn-link" onClick={() => setCreating(true)}>
              Spravovat firemní Macy z tohoto Macu
            </button>
          </p>
        </>
      ) : null}
      {error ? <p className="notice tone-alert">{error}</p> : null}

      {preview ? (
        <JoinDialog
          preview={preview}
          code={code.trim()}
          onClose={() => setPreview(null)}
          onJoined={() => {
            setPreview(null);
            setCode("");
            void fleet.refresh();
          }}
        />
      ) : null}
      {creating ? (
        <CreateDialog
          onClose={() => setCreating(false)}
          onCreated={() => {
            setCreating(false);
            void fleet.refresh();
          }}
        />
      ) : null}
    </section>
  );
}
