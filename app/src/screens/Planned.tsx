// Stránky funkcí, které ve verzi 0.1 neexistují. Říkají to přímo.
export type PlannedFeature = "realtime" | "quarantine" | "systemcare";

const CONTENT: Record<PlannedFeature, { title: string; what: string; why: string; needs: string[] }> = {
  realtime: {
    title: "Ochrana v reálném čase",
    what: "Bude kontrolovat soubory ve chvíli, kdy se otevírají nebo spouštějí, a nebezpečné zablokuje.",
    why: "Ve verzi 0.1 neběží. Soubory se kontrolují jen tehdy, když je sami vyberete.",
    needs: [
      "Mac: oprávnění Endpoint Security od Apple, účet Apple Developer a systémové rozšíření",
      "Windows: ovladač systému souborů podepsaný přes Microsoft",
      "Plný přístup k disku povolený uživatelem",
    ],
  },
  quarantine: {
    title: "Karanténa",
    what: "Přesune nalezený soubor do zašifrovaného úložiště, odkud ho půjde auditovatelně obnovit.",
    why: "Ve verzi 0.1 aplikace soubory jen čte a nic nepřesouvá ani nemaže.",
    needs: [
      "Ověření, že soubor je stejný jako při kontrole",
      "Šifrovaná kopie ověřená před odstraněním originálu",
      "Obnova jen na pokyn uživatele, se záznamem v auditu",
    ],
  },
  systemcare: {
    title: "System Care",
    what: "Bude hledat nepotřebné soubory a pomáhat uvolnit místo.",
    why: "Ve verzi 0.1 neexistuje. Mazání souborů je samo bezpečnostní riziko a potřebuje vlastní návrh.",
    needs: ["Bezpečnostní návrh mazání", "Potvrzení každé změny uživatelem", "Záznam v auditu"],
  },
};

export function Planned({ feature }: { feature: PlannedFeature }) {
  const c = CONTENT[feature];
  return (
    <div className="screen planned">
      <h1>{c.title}</h1>
      <p className="status-chip">Není ve verzi 0.1</p>
      <p className="lede">{c.what}</p>
      <p>{c.why}</p>
      <section className="panel">
        <h2>Co bude potřeba</h2>
        <ul>
          {c.needs.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      </section>
    </div>
  );
}
