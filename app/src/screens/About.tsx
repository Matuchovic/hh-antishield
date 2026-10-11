import { describeError, formatCount, formatDateTime } from "../lib/format";
import type { AntiShield } from "../lib/useAntiShield";
import type { Updater } from "../lib/useUpdater";

const NOTICES: { name: string; license: string }[] = [
  { name: "Tauri a jeho pluginy", license: "MIT nebo Apache-2.0" },
  { name: "React", license: "MIT" },
  { name: "YARA-X (VirusTotal)", license: "BSD-3-Clause" },
  { name: "Wasmtime, Cranelift", license: "Apache-2.0 s výjimkou LLVM" },
  { name: "RustCrypto sha2, rustls, reqwest", license: "MIT nebo Apache-2.0 (ring: ISC)" },
  { name: "ed25519-dalek, curve25519-dalek, subtle", license: "BSD-3-Clause" },
  { name: "aho-corasick, memchr, walkdir", license: "MIT nebo Unlicense" },
  { name: "zip, sysinfo, plist, chrono", license: "MIT (chrono: MIT nebo Apache-2.0)" },
  { name: "notify", license: "CC0-1.0" },
  { name: "serde, serde_json, uuid, thiserror", license: "MIT nebo Apache-2.0" },
  { name: "Písmo Barlow (Jeremy Tribby)", license: "SIL Open Font License 1.1" },
];

const UPDATE_TEXT = {
  idle: "Aplikace kontroluje aktualizace hned po spuštění, každých 5 minut a při návratu do okna.",
  checking: "Kontroluji…",
  upToDate: "Máte nejnovější verzi.",
  installing: "Instaluji aktualizaci…",
} as const;

export function About({ app, updater }: { app: AntiShield; updater: Updater }) {
  const { info, selfTest } = app;
  return (
    <div className="screen">
      <h1>O aplikaci</h1>
      <p className="lede">
        H&amp;H AntiShield kontroluje soubory pravidly YARA a otisky, hlídá vybrané složky, izoluje
        hrozby do karantény a sám se aktualizuje. Spouštění programů zatím neblokuje; to vyžaduje
        rozšíření Endpoint Security od Applu.
      </p>
      <dl className="facts">
        <div>
          <dt>Aplikace</dt>
          <dd>{__APP_VERSION__}</dd>
        </div>
        <div>
          <dt>Engine</dt>
          <dd>{info ? `${info.engineVersion} (${info.platform})` : "nenačten"}</dd>
        </div>
        <div>
          <dt>Sada pravidel</dt>
          <dd>
            {info
              ? `${info.rulePack.packId} ${info.rulePack.version}, ${formatCount(info.rulePack.ruleCount, "pravidlo", "pravidla", "pravidel")}${info.rulePack.testPack ? ", testovací" : ""}`
              : "nenačtena"}
          </dd>
        </div>
        <div>
          <dt>Podpis pravidel</dt>
          <dd>{info ? `Ed25519, klíč ${info.rulePack.signingKeyId}` : "neověřen"}</dd>
        </div>
      </dl>

      <section className="panel" aria-labelledby="update-title">
        <div className="panel-head">
          <h2 id="update-title">Aktualizace</h2>
          <button
            type="button"
            className="btn-secondary"
            disabled={updater.status === "checking" || updater.status === "installing"}
            onClick={() => void updater.check()}
          >
            Zkontrolovat aktualizace
          </button>
        </div>
        <p className={updater.status === "error" ? "tone-text-alert" : "muted"}>
          {updater.status === "available" && updater.info
            ? `Je k dispozici verze ${updater.info.version}, nainstalujete ji z banneru nahoře.`
            : updater.status === "error" && updater.error
              ? describeError(updater.error)
              : UPDATE_TEXT[updater.status === "available" || updater.status === "error" ? "idle" : updater.status]}
        </p>
        <p className="muted">Aktualizace jsou podepsané klíčem H&amp;H; aplikace nepodepsanou aktualizaci odmítne.</p>
      </section>

      <section className="panel" aria-labelledby="selftest-title">
        <div className="panel-head">
          <h2 id="selftest-title">Self-test enginu</h2>
          <button type="button" className="btn-secondary" onClick={() => void app.runSelfTest()}>
            Spustit self-test
          </button>
        </div>
        {selfTest ? (
          <>
            <p>
              {selfTest.passed ? "Prošel" : "Selhal"} v {formatDateTime(selfTest.ranAtMs)}
            </p>
            <ul className="checks">
              {selfTest.checks.map((c) => (
                <li key={c.name} className={c.passed ? "tone-good" : "tone-alert"}>
                  <span className="dot" aria-hidden="true" /> {c.detail}
                </li>
              ))}
            </ul>
          </>
        ) : (
          <p className="muted">
            Self-test proběhl při startu aplikace. Výsledek ukazuje stav komponent na přehledu.
          </p>
        )}
      </section>

      {info?.rulePack.sources.length ? (
        <section className="panel" aria-labelledby="sources-title">
          <h2 id="sources-title">Zdroje pravidel</h2>
          <p className="muted">Pravidla YARA od těchto autorů; licence dovolují komerční použití.</p>
          <table className="table">
            <tbody>
              {info.rulePack.sources.map((source) => (
                <tr key={source.id}>
                  <th scope="row">{source.name}</th>
                  <td>{source.license}</td>
                  <td>{formatCount(source.ruleCount, "pravidlo", "pravidla", "pravidel")}</td>
                  <td className="muted">{source.url}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ) : null}

      <section className="panel" aria-labelledby="licenses-title">
        <h2 id="licenses-title">Software třetích stran</h2>
        <table className="table">
          <tbody>
            {NOTICES.map((n) => (
              <tr key={n.name}>
                <th scope="row">{n.name}</th>
                <td>{n.license}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="muted">Úplný seznam licencí bude součástí instalačního balíčku.</p>
      </section>
    </div>
  );
}
