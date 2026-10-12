import { useState } from "react";
import { api, asError } from "../lib/api";
import { agoText, categoryList, groupFingerprint } from "../lib/fleet";
import { capitalize, describeError, formatBytes, formatCount, formatDate } from "../lib/format";
import type { FleetApproval, FleetJoinPreview, FleetPolicy } from "../lib/types";
import type { Fleet } from "../lib/useFleet";
import { Icon } from "./Icon";
import { Sheet } from "./Sheet";

/** Co správce firmy uvidí a smí; stejný text při připojení i potom. */
export function PolicyLists({ policy }: { policy: FleetPolicy }) {
  return (
    <div className="policy-lists">
      <section className="policy-col">
        <h4>
          <Icon name="search" size={16} /> Správce uvidí
        </h4>
        <ul>
          <li>stav ochrany, pravidel a poslední kontroly</li>
          <li>nalezené hrozby: název a umístění souboru</li>
          <li>místo na disku, paměť a dobu od restartu</li>
          <li>kolik jde uklidit, jen velikosti bez názvů souborů</li>
        </ul>
      </section>
      <section className="policy-col">
        <h4>
          <Icon name="sparkle" size={16} /> Smí na dálku
        </h4>
        <ul>
          <li>spustit kontrolu a izolovat nalezené hrozby do karantény</li>
          <li>uklidit {categoryList(policy.auto)}</li>
        </ul>
      </section>
      {policy.consent.length ? (
        <section className="policy-col is-consent">
          <h4>
            <Icon name="check" size={16} /> Jen s vaším souhlasem
          </h4>
          <ul>
            <li>{capitalize(categoryList(policy.consent))}. Přesunou se do Koše, odkud je jde vrátit.</li>
          </ul>
        </section>
      ) : null}
      <section className="policy-col is-never">
        <h4>
          <Icon name="lock" size={16} /> Nikdy
        </h4>
        <ul>
          <li>vaše dokumenty, fotky, zprávy, hesla ani historie prohlížeče se z Macu neposílají</li>
          <li>velké soubory a Koš na dálku nesmaže</li>
          <li>ochranu ani nastavení na dálku nezmění</li>
        </ul>
      </section>
    </div>
  );
}

/** Žádosti správce, které čekají na souhlas uživatele (nahoře na každé obrazovce). */
export function FleetApprovals({ fleet }: { fleet: Fleet }) {
  const [busy, setBusy] = useState<string | null>(null);
  const member = fleet.member;
  if (!member || !member.approvals.length) return null;
  const decide = async (approval: FleetApproval, approve: boolean) => {
    setBusy(approval.id);
    try {
      fleet.setMember(await api.fleetApprove(approval.id, approve));
    } finally {
      setBusy(null);
    }
  };
  return (
    <>
      {member.approvals.map((approval) => (
        <div key={approval.id} className="fleet-approval" role="status">
          <span className="fleet-approval-icon" aria-hidden="true">
            <Icon name="building" size={20} />
          </span>
          <p>
            <strong>{member.adminName} navrhuje úklid</strong>
            <span>
              {capitalize(categoryList(approval.categories))}, {formatBytes(approval.bytes)}. Přesune se do Koše, odkud to
              jde vrátit.
            </span>
          </p>
          <div className="actions">
            <button
              type="button"
              className="btn-secondary btn-small"
              disabled={busy !== null}
              onClick={() => void decide(approval, true)}
            >
              {busy === approval.id ? "Uklízím…" : "Uklidit"}
            </button>
            <button type="button" className="btn-link" disabled={busy !== null} onClick={() => void decide(approval, false)}>
              Teď ne
            </button>
          </div>
        </div>
      ))}
    </>
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
