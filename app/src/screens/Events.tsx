import { describeAuditEvent, formatDateTime } from "../lib/format";
import type { AntiShield } from "../lib/useAntiShield";

export function Events({ app }: { app: AntiShield }) {
  return (
    <div className="screen">
      <div className="panel-head">
        <h1>Události</h1>
        <button type="button" className="btn-secondary" onClick={() => void app.refresh()}>
          Načíst znovu
        </button>
      </div>
      <p className="lede">
        Auditní log zaznamenává start enginu, ověření pravidel, kontroly a nálezy. Každý záznam je
        řetězený s předchozím, takže pozdější úprava je poznat.
      </p>
      {app.engineError ? <p className="notice tone-alert">{app.engineError.message}</p> : null}
      {app.events.length ? (
        <table className="table events">
          <thead>
            <tr>
              <th scope="col">Čas</th>
              <th scope="col">Událost</th>
              <th scope="col">Podrobnosti</th>
            </tr>
          </thead>
          <tbody>
            {app.events.map((event) => {
              const d = describeAuditEvent(event);
              return (
                <tr key={event.seq}>
                  <td>{formatDateTime(event.tsMs)}</td>
                  <td>{d.title}</td>
                  <td className="muted">{d.detail}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      ) : (
        <p className="muted">Zatím žádné události.</p>
      )}
    </div>
  );
}
