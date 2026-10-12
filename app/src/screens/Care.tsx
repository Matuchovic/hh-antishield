import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Icon } from "../components/Icon";
import { Toggle } from "../components/Toggle";
import { Vortex, type VortexGroup, type VortexPhase } from "../components/Vortex";
import { api, asError, onCleanProgress } from "../lib/api";
import {
  CATEGORIES,
  CATEGORY_ORDER,
  type CareTone,
  cpuTone,
  defaultSelection,
  diskTone,
  failureText,
  groupByCategory,
  memoryTone,
  methodText,
  noteText,
  PRESSURE_TEXT,
  selectedBytes,
  speedAdvice,
  startupName,
  trashItem,
  uptimeText,
  uptimeTone,
} from "../lib/care";
import { describeError, displayPath, formatBytes } from "../lib/format";
import type {
  CleanCategory,
  CleanItem,
  CleanOutcome,
  CleanScan,
  HeavyProcess,
  SpeedReport,
} from "../lib/types";
import { useCountUp } from "../lib/useCountUp";
import type { AntiShield } from "../lib/useAntiShield";

function motionReduced(app: AntiShield): boolean {
  return Boolean(app.settings?.reducedMotion) || window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/** Velikost, která plynule doběhne k cíli (bajty). */
function Bytes({ value }: { value: number }) {
  return <>{formatBytes(useCountUp(value, 1100))}</>;
}

// ---------- Čištění ----------

interface Done {
  outcome: CleanOutcome;
  items: CleanItem[];
  emptiedTrash: boolean;
}

function CategoryCheck({
  state,
  label,
  onChange,
}: {
  state: "all" | "some" | "none";
  label: string;
  onChange: (next: boolean) => void;
}) {
  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={state === "all" ? true : state === "some" ? "mixed" : false}
      aria-label={label}
      className={`care-check is-${state}`}
      onClick={() => onChange(state !== "all")}
    >
      <Icon name="check" />
    </button>
  );
}

function CleanPanel({ app, onError }: { app: AntiShield; onError: (text: string | null) => void }) {
  const still = motionReduced(app);
  const [scan, setScan] = useState<CleanScan | null>(null);
  const [phase, setPhase] = useState<VortexPhase>("idle");
  const [active, setActive] = useState<CleanCategory | null>(null);
  const [visited, setVisited] = useState<CleanCategory[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [focus, setFocus] = useState<CleanCategory | null>(null);
  const [review, setReview] = useState(false);
  const [done, setDone] = useState<Done | null>(null);
  const [confirmTrash, setConfirmTrash] = useState(false);
  const [stopped, setStopped] = useState(false);
  const activeRef = useRef<CleanCategory | null>(null);
  const stageRef = useRef<HTMLDivElement>(null);
  // V úzkém okně je plátno nad tlačítky: při úklidu ho ukázat celé.
  const showStage = () => stageRef.current?.scrollIntoView({ block: "nearest" });

  useEffect(() => {
    void api
      .cleanLast()
      .then((last) => {
        if (!last) return;
        setScan(last);
        setSelected(defaultSelection(last));
        setPhase((p) => (p === "idle" ? "ready" : p));
      })
      .catch(() => undefined);
  }, []);

  const startScan = useCallback(async () => {
    onError(null);
    setPhase("scanning");
    setActive(null);
    setVisited([]);
    setDone(null);
    setStopped(false);
    setConfirmTrash(false);
    activeRef.current = null;
    const stop = await onCleanProgress((category) => {
      const previous = activeRef.current;
      if (previous) setVisited((list) => (list.includes(previous) ? list : [...list, previous]));
      activeRef.current = category;
      setActive(category);
    });
    try {
      const result = await api.cleanScan();
      setScan(result);
      setSelected(defaultSelection(result));
      setPhase("ready");
    } catch (error) {
      onError(describeError(asError(error)));
      setPhase(scan ? "ready" : "idle");
    } finally {
      stop();
      setActive(null);
    }
  }, [onError, scan]);

  const stopScan = () => {
    setStopped(true);
    void api.cleanCancel();
  };

  const finish = (result: CleanOutcome, items: CleanItem[], emptiedTrash: boolean) => {
    setScan((current) =>
      current ? { ...current, items: current.items.filter((i) => !result.cleaned.includes(i.id)) } : current,
    );
    setDone({ outcome: result, items, emptiedTrash });
    setSelected(new Set());
    setPhase("done");
  };

  const clean = async () => {
    if (!scan) return;
    const ids = [...selected];
    const items = scan.items.filter((i) => selected.has(i.id));
    onError(null);
    setPhase("cleaning");
    setConfirmTrash(false);
    showStage();
    try {
      // Jádro se nejdřív „nabije“ (částice vybraných kategorií zrychlí).
      const [result] = await Promise.all([
        api.cleanItems(ids),
        new Promise((resolve) => setTimeout(resolve, still ? 0 : 900)),
      ]);
      finish(result, items, false);
    } catch (error) {
      onError(describeError(asError(error)));
      setPhase("ready");
    }
  };

  const emptyTrash = async () => {
    if (!scan) return;
    const trash = trashItem(scan);
    onError(null);
    setPhase("cleaning");
    setConfirmTrash(false);
    try {
      const result = await api.cleanEmptyTrash();
      finish(result, trash ? [trash] : [], true);
    } catch (error) {
      onError(describeError(asError(error)));
      setPhase("ready");
    }
  };

  const groups = useMemo(() => (scan ? groupByCategory(scan) : []), [scan]);
  const vortexGroups: VortexGroup[] = useMemo(
    () =>
      groups.map((g) => ({
        category: g.category,
        bytes: g.bytes,
        selected: g.items.some((i) => selected.has(i.id)),
      })),
    [groups, selected],
  );
  const totals = scan ? selectedBytes(scan, selected) : { freed: 0, trashed: 0, total: 0, count: 0 };
  const trash = scan ? trashItem(scan) : null;
  const toggleItems = (items: CleanItem[], on: boolean) => {
    setSelected((current) => {
      const next = new Set(current);
      for (const item of items) {
        if (item.method === "emptyTrash") continue;
        if (on) next.add(item.id);
        else next.delete(item.id);
      }
      return next;
    });
  };
  const categoryState = (items: CleanItem[]): "all" | "some" | "none" => {
    const n = items.filter((i) => selected.has(i.id)).length;
    return n === 0 ? "none" : n === items.length ? "all" : "some";
  };
  const busy = phase === "scanning" || phase === "cleaning";
  const trashUnreadable = scan?.unreadable.some((p) => /[\\/]\.?Trash/i.test(p)) ?? false;
  const failed = done?.outcome.failed ?? [];

  return (
    <>
      <section className={`panel vortex-panel is-${phase}`} aria-labelledby="clean-title">
        <div className="vortex-stage" ref={stageRef}>
          <Vortex phase={phase} groups={vortexGroups} active={active} focus={focus} still={still} />
        </div>
        <div className="vortex-side" aria-live="polite">
          {phase === "idle" ? (
            <>
              <h2 id="clean-title" className="care-title">
                Kolik místa jde uvolnit?
              </h2>
              <p className="muted">
                Hledání projde mezipaměti aplikací, staré protokoly, instalátory, zbytky po odinstalovaných
                aplikacích a velké staré soubory ve vaší složce. Systému, fotek ani pošty se nedotkne.
              </p>
              <div className="actions">
                <button type="button" className="care-cta" onClick={() => void startScan()}>
                  <Icon name="search" />
                  Najít, co zabírá místo
                </button>
              </div>
            </>
          ) : null}

          {phase === "scanning" ? (
            <>
              <h2 id="clean-title" className="care-title">
                Hledání běží
              </h2>
              <ol className="scan-steps">
                {CATEGORY_ORDER.map((cat) => {
                  const state = visited.includes(cat) ? "done" : active === cat ? "active" : "waiting";
                  return (
                    <li key={cat} className={`is-${state}`} style={{ "--cat": CATEGORIES[cat].rgb } as React.CSSProperties}>
                      <span className="step-dot" aria-hidden="true" />
                      <span>{CATEGORIES[cat].label}</span>
                      <span className="step-state">
                        {state === "done" ? "prošlo" : state === "active" ? "prochází se" : ""}
                      </span>
                    </li>
                  );
                })}
              </ol>
              <div className="actions">
                <button type="button" className="btn-secondary" onClick={stopScan} disabled={stopped}>
                  {stopped ? "Zastavuji…" : "Zastavit"}
                </button>
              </div>
            </>
          ) : null}

          {(phase === "ready" || phase === "cleaning") && scan ? (
            <>
              <p className="care-figure">
                <span className="care-number">
                  <Bytes value={totals.total} />
                </span>
                <span className="care-caption" id="clean-title">
                  {phase === "cleaning"
                    ? "Probíhá úklid…"
                    : totals.count
                      ? "můžete uvolnit"
                      : groups.length
                        ? "Nic není vybrané"
                        : "Nic zbytečného se nenašlo"}
                </span>
              </p>
              {groups.length ? (
                <ul className="care-legend" onMouseLeave={() => setFocus(null)}>
                  {groups.map((g) => {
                    const meta = CATEGORIES[g.category];
                    const isTrash = g.category === "trash";
                    return (
                      <li
                        key={g.category}
                        style={{ "--cat": meta.rgb } as React.CSSProperties}
                        onMouseEnter={() => setFocus(g.category)}
                        className={focus === g.category ? "is-focus" : undefined}
                      >
                        {isTrash ? (
                          <span className="care-check is-placeholder" aria-hidden="true" />
                        ) : (
                          <CategoryCheck
                            state={categoryState(g.items)}
                            label={`Vybrat: ${meta.label}`}
                            onChange={(on) => toggleItems(g.items, on)}
                          />
                        )}
                        <span className="legend-dot" aria-hidden="true" />
                        <span className="legend-text">
                          <span className="legend-label">{meta.label}</span>
                          <span className="legend-what">
                            {isTrash ? "Vysypání je nevratné" : methodText(g.items[0]?.method ?? "delete")}
                          </span>
                        </span>
                        <span className="legend-size">{formatBytes(g.bytes)}</span>
                      </li>
                    );
                  })}
                </ul>
              ) : null}
              {totals.trashed > 0 ? (
                <p className="care-note">
                  Z toho {formatBytes(totals.trashed)} půjde do Koše, odkud ho můžete vrátit.
                </p>
              ) : null}
              {!scan.complete ? (
                <p className="care-note">Hledání nedoběhlo celé, výsledek nemusí být úplný.</p>
              ) : null}
              {trashUnreadable ? (
                <p className="care-note">Koš jde zkontrolovat jen s plným přístupem k disku.</p>
              ) : null}
              <div className="actions">
                <button
                  type="button"
                  className="care-cta"
                  disabled={busy || totals.count === 0}
                  onClick={() => void clean()}
                >
                  <Icon name="sparkle" />
                  {phase === "cleaning" ? "Uklízím…" : `Vyčistit ${formatBytes(totals.total)}`}
                </button>
                <button type="button" className="btn-secondary" disabled={busy} onClick={() => setReview((v) => !v)}>
                  {review ? "Skrýt položky" : "Projít položky"}
                </button>
                <button type="button" className="btn-link" disabled={busy} onClick={() => void startScan()}>
                  Hledat znovu
                </button>
              </div>
            </>
          ) : null}

          {phase === "done" && done ? (
            <>
              <p className="care-figure is-done">
                <span className="care-number">
                  <Bytes value={done.outcome.freedBytes + done.outcome.trashedBytes} />
                </span>
                <span className="care-caption" id="clean-title">
                  {done.emptiedTrash ? "Koš je prázdný" : "uklizeno"}
                </span>
              </p>
              <ul className="care-result">
                {done.outcome.freedBytes > 0 ? (
                  <li>
                    <Icon name="check" /> Uvolněno hned: {formatBytes(done.outcome.freedBytes)}
                  </li>
                ) : null}
                {done.outcome.trashedBytes > 0 ? (
                  <li>
                    <Icon name="trash" /> V Koši: {formatBytes(done.outcome.trashedBytes)}. Místo se uvolní po jeho
                    vysypání.
                  </li>
                ) : null}
                {failed.length ? (
                  <li className="is-failed">
                    <Icon name="warning" />
                    {failed.length === 1 ? "Jedna položka zůstala" : `${failed.length} položek zůstalo`}:{" "}
                    {failureText(failed[0]?.reason ?? "")}
                  </li>
                ) : null}
              </ul>
              <div className="actions">
                <button type="button" className="care-cta" onClick={() => void startScan()}>
                  <Icon name="search" />
                  Hledat znovu
                </button>
                {groups.length ? (
                  <button type="button" className="btn-secondary" onClick={() => setPhase("ready")}>
                    Zbylé položky
                  </button>
                ) : null}
              </div>
            </>
          ) : null}

          {trash && (phase === "ready" || phase === "done") ? (
            <div className={`trash-row${confirmTrash ? " is-confirm" : ""}`}>
              {confirmTrash ? (
                <>
                  <p>
                    Vysypat Koš ({formatBytes(trash.bytes)})? Soubory v něm už nepůjde vrátit.
                  </p>
                  <div className="actions">
                    <button type="button" className="btn-danger" onClick={() => void emptyTrash()}>
                      Vysypat Koš
                    </button>
                    <button type="button" className="btn-link" onClick={() => setConfirmTrash(false)}>
                      Ponechat
                    </button>
                  </div>
                </>
              ) : (
                <>
                  <p>
                    V Koši je {formatBytes(trash.bytes)}. Místo se uvolní až po jeho vysypání.
                  </p>
                  <button type="button" className="btn-link" onClick={() => setConfirmTrash(true)}>
                    Vysypat…
                  </button>
                </>
              )}
            </div>
          ) : null}
        </div>
      </section>

      {review && scan && phase === "ready" ? (
        <section className="panel care-review" aria-label="Nalezené položky">
          {groups
            .filter((g) => g.category !== "trash")
            .map((g) => {
              const meta = CATEGORIES[g.category];
              return (
                <div key={g.category} className="review-group" style={{ "--cat": meta.rgb } as React.CSSProperties}>
                  <div className="review-head">
                    <CategoryCheck
                      state={categoryState(g.items)}
                      label={`Vybrat: ${meta.label}`}
                      onChange={(on) => toggleItems(g.items, on)}
                    />
                    <span className="legend-dot" aria-hidden="true" />
                    <span className="review-title">{meta.label}</span>
                    <span className="review-what">{meta.what}</span>
                    <span className="legend-size">{formatBytes(g.bytes)}</span>
                  </div>
                  <ul className="review-items">
                    {g.items.map((item) => {
                      const note = noteText(item.note);
                      const on = selected.has(item.id);
                      return (
                        <li key={item.id} className={on ? "is-on" : undefined}>
                          <CategoryCheck
                            state={on ? "all" : "none"}
                            label={`Vybrat: ${item.name}`}
                            onChange={(next) => toggleItems([item], next)}
                          />
                          <span className="item-text">
                            <span className="item-name">{item.name}</span>
                            <span className="item-path" title={displayPath(item.path)}>
                              {/* Značky LRM drží lomítka na místě při zkrácení zleva. */}
                              {`\u200e${displayPath(item.path)}\u200e`}
                            </span>
                            {note ? <span className="item-note">{note}</span> : null}
                          </span>
                          <span className="item-method">{methodText(item.method)}</span>
                          <span className="legend-size">{formatBytes(item.bytes)}</span>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              );
            })}
        </section>
      ) : null}
    </>
  );
}

// ---------- Zrychlení ----------

const TONE_TEXT: Record<CareTone, string> = { good: "V pořádku", caution: "Pozor", alert: "Brzdí" };

function Gauge({
  value,
  tone,
  title,
  primary,
  secondary,
}: {
  value: number;
  tone: CareTone;
  title: string;
  primary: string;
  secondary: string;
}) {
  // Oblouk 270°: délka 0,75 obvodu kružnice s poloměrem 52.
  const arc = 2 * Math.PI * 52 * 0.75;
  const fill = Math.max(0, Math.min(1, value)) * arc;
  return (
    <figure className={`gauge tone-${tone}`}>
      <svg viewBox="0 0 128 128" aria-hidden="true">
        <circle className="gauge-track" cx="64" cy="64" r="52" strokeDasharray={`${arc} 999`} />
        <circle className="gauge-fill" cx="64" cy="64" r="52" strokeDasharray={`${fill} 999`} />
      </svg>
      <div className="gauge-center">
        <span className="gauge-primary">{primary}</span>
        <span className="gauge-tone">{TONE_TEXT[tone]}</span>
      </div>
      <figcaption>
        <span className="gauge-title">{title}</span>
        <span className="gauge-secondary">{secondary}</span>
      </figcaption>
    </figure>
  );
}

function HeavyRow({
  process,
  state,
  onQuit,
}: {
  process: HeavyProcess;
  state: string | undefined;
  onQuit: () => void;
}) {
  const share = Math.min(100, process.cpu);
  return (
    <li className="heavy-row">
      <span className="heavy-mark" aria-hidden="true">
        {process.name.slice(0, 1).toUpperCase()}
      </span>
      <span className="heavy-text">
        <span className="heavy-name">{process.name}</span>
        <span className="heavy-detail">
          {process.processes > 1 ? `${process.processes} procesů, ` : ""}
          {formatBytes(process.memory)} paměti
        </span>
        <span className="heavy-bar" aria-hidden="true">
          <span style={{ transform: `scaleX(${share / 100})` }} />
        </span>
      </span>
      <span className="heavy-cpu">{Math.round(process.cpu)} %</span>
      {state === "quit" ? (
        <span className="heavy-state">Ukončeno</span>
      ) : state === "pending" ? (
        <span className="heavy-state">Čeká na vás (uložení práce)</span>
      ) : (
        <button type="button" className="btn-secondary btn-small" disabled={state === "busy"} onClick={onQuit}>
          {state === "busy" ? "Žádám…" : "Ukončit"}
        </button>
      )}
    </li>
  );
}

function SpeedPanel({
  app,
  onError,
  onFreeSpace,
}: {
  app: AntiShield;
  onError: (text: string | null) => void;
  onFreeSpace: () => void;
}) {
  const [report, setReport] = useState<SpeedReport | null>(null);
  const [measuring, setMeasuring] = useState(false);
  const [quit, setQuit] = useState<Record<number, string>>({});
  const [toggling, setToggling] = useState<string | null>(null);
  const still = motionReduced(app);

  const measure = useCallback(async () => {
    setMeasuring(true);
    try {
      setReport(await api.speedReport());
    } catch (error) {
      onError(describeError(asError(error)));
    } finally {
      setMeasuring(false);
    }
  }, [onError]);

  useEffect(() => {
    void measure();
  }, [measure]);

  const quitApp = async (process: HeavyProcess) => {
    onError(null);
    setQuit((q) => ({ ...q, [process.pid]: "busy" }));
    try {
      const outcome = await api.speedQuit(process.pid);
      setQuit((q) => ({ ...q, [process.pid]: outcome }));
      if (outcome === "quit") setTimeout(() => void measure(), 900);
    } catch (error) {
      setQuit((q) => ({ ...q, [process.pid]: "" }));
      onError(describeError(asError(error)));
    }
  };

  const setStartup = async (id: string, enabled: boolean) => {
    onError(null);
    setToggling(id);
    try {
      setReport(await api.speedStartup(id, enabled));
    } catch (error) {
      onError(describeError(asError(error)));
    } finally {
      setToggling(null);
    }
  };

  const advice = report ? speedAdvice(report) : [];
  const userStartup = report?.startup.filter((e) => !e.system) ?? [];
  const systemStartup = report?.startup.filter((e) => e.system) ?? [];
  const disk = report?.disk ?? null;
  const memory = report?.memory;

  return (
    <section className={`panel speed-panel${measuring ? " is-measuring" : ""}`} aria-labelledby="speed-title">
      <div className="panel-head">
        <h2 id="speed-title">Zrychlení</h2>
        <button type="button" className="btn-secondary btn-small" disabled={measuring} onClick={() => void measure()}>
          {measuring ? "Měřím…" : "Změřit znovu"}
        </button>
      </div>

      {report && memory ? (
        <>
          <div className={`gauges${still ? " is-still" : ""}`} key={report.measuredAtMs}>
            <Gauge
              title="Volné místo"
              value={disk && disk.total > 0 ? 1 - disk.free / disk.total : 0}
              tone={diskTone(disk)}
              primary={disk ? formatBytes(disk.free) : "Neznámé"}
              secondary={disk ? `z ${formatBytes(disk.total)}` : ""}
            />
            <Gauge
              title="Paměť"
              value={memory.total > 0 ? memory.used / memory.total : 0}
              tone={memoryTone(memory)}
              primary={`${Math.round((memory.used / Math.max(1, memory.total)) * 100)} %`}
              secondary={
                memory.pressure
                  ? PRESSURE_TEXT[memory.pressure]
                  : `${formatBytes(memory.used)} z ${formatBytes(memory.total)}`
              }
            />
            <Gauge
              title="Procesor"
              value={report.cpu / 100}
              tone={cpuTone(report.cpu)}
              primary={`${Math.round(report.cpu)} %`}
              secondary={`${report.cores} jader`}
            />
            <figure className={`uptime tone-${uptimeTone(report.uptimeSecs)}`}>
              <Icon name="clock" />
              <span className="uptime-value">{uptimeText(report.uptimeSecs)}</span>
              <figcaption>bez restartu</figcaption>
              {memory.swapUsed > 0 ? (
                <span className="uptime-swap">Odloženo na disk {formatBytes(memory.swapUsed)}</span>
              ) : null}
            </figure>
          </div>

          <ul className="advice">
            {advice.length ? (
              advice.map((a) => (
                <li key={a.text} className={`tone-${a.tone}`}>
                  <span className="dot" aria-hidden="true" />
                  <span>{a.text}</span>
                  {a.text.startsWith("Na disku") ? (
                    <button type="button" className="btn-link" onClick={onFreeSpace}>
                      Uvolnit místo
                    </button>
                  ) : null}
                </li>
              ))
            ) : (
              <li className="tone-good">
                <span className="dot" aria-hidden="true" />
                <span>Počítač teď nic nebrzdí.</span>
              </li>
            )}
          </ul>

          <div className="speed-cols">
            <section aria-labelledby="heavy-title">
              <h3 id="heavy-title">Co teď zatěžuje počítač</h3>
              {report.heavy.length ? (
                <ul className="heavy-list">
                  {report.heavy.map((p) => (
                    <HeavyRow key={p.pid} process={p} state={quit[p.pid]} onQuit={() => void quitApp(p)} />
                  ))}
                </ul>
              ) : (
                <p className="muted">Žádná aplikace teď počítač výrazně nezatěžuje.</p>
              )}
              <p className="care-note">
                Ukončit znamená požádat aplikaci o běžné zavření, jako byste ji zavřeli sami. Rozdělanou práci si
                nechá uložit.
              </p>
            </section>
            <section aria-labelledby="startup-title">
              <h3 id="startup-title">Spouští se po přihlášení</h3>
              {userStartup.length ? (
                <div className="startup-list">
                  {userStartup.map((entry) => (
                    <Toggle
                      key={entry.id}
                      checked={entry.enabled}
                      disabled={toggling !== null}
                      label={startupName(entry)}
                      detail={
                        toggling === entry.id
                          ? "Měním…"
                          : !entry.enabled
                            ? "Vypnuto, jde kdykoli vrátit"
                            : entry.pid
                              ? `Běží, ${formatBytes(entry.memory)} paměti`
                              : "Zapnuto"
                      }
                      onChange={(on) => void setStartup(entry.id, on)}
                    />
                  ))}
                </div>
              ) : (
                <p className="muted">Ve vašem účtu se po přihlášení nic dalšího nespouští.</p>
              )}
              {systemStartup.length ? (
                <p className="care-note">
                  Dalších {systemStartup.length} položek je pro celý systém. Ty se spravují v Nastavení systému.{" "}
                  <button
                    type="button"
                    className="btn-link"
                    onClick={() => void api.openSystemSettings("loginItems").catch(() => undefined)}
                  >
                    Otevřít položky po přihlášení
                  </button>
                </p>
              ) : null}
            </section>
          </div>
        </>
      ) : (
        <p className="muted">{measuring ? "Měřím stav počítače…" : "Stav počítače se nepodařilo změřit."}</p>
      )}
    </section>
  );
}

export function Care({ app }: { app: AntiShield }) {
  const [error, setError] = useState<string | null>(null);
  const cleanRef = useRef<HTMLDivElement>(null);
  const onError = useCallback((text: string | null) => setError(text), []);
  return (
    <div className="screen care">
      <div>
        <h1>Čištění a zrychlení</h1>
        <p className="lede">
          Najde, co ve vaší složce zbytečně zabírá místo, a změří, co počítač zpomaluje. Bez vašeho potvrzení nic
          nesmaže a nic neukončí.
        </p>
      </div>
      {error ? (
        <p className="notice tone-alert" role="alert">
          {error}
        </p>
      ) : null}
      <div ref={cleanRef} className="care-clean">
        <CleanPanel app={app} onError={onError} />
      </div>
      <SpeedPanel
        app={app}
        onError={onError}
        onFreeSpace={() => cleanRef.current?.scrollIntoView({ behavior: "smooth", block: "start" })}
      />
    </div>
  );
}
