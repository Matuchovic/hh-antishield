# H&H AntiShield

Desktopová aplikace pro macOS a Windows (Tauri 2 + Rust). Verze **0.1 je ruční
skener souborů**: kontroluje jen soubory a složky, které uživatel vybere.
Ochranu v reálném čase, karanténu ani automatické aktualizace pravidel zatím
nemá a aplikace to na přehledu otevřeně říká. Přesný stav je v
[docs/feature-status.md](docs/feature-status.md).

Projekt je samostatný: nesdílí kód, účty, klíče ani nasazení s hhsecurity
ani hhcloud.

## Instalace (v0.1, bez App Store)

Balíčky staví GitHub Actions (workflow **Release**) a jsou ke stažení jako
artefakty běhu, později z webu AntiShieldu.

**macOS 12 a novější (Apple Silicon i Intel)** – soubor `.dmg`:
1. Otevřete DMG a přetáhněte H&H AntiShield do Aplikací.
2. Při prvním spuštění macOS aplikaci zablokuje, protože není podepsaná
   Apple Developer ID. Otevřete *Nastavení systému → Soukromí a zabezpečení*
   a u hlášení o H&H AntiShield klikněte na *Přesto otevřít*.
3. Povolení platí jen pro tuto verzi. Gatekeeper zůstává zapnutý pro vše
   ostatní; nikdy ho nevypínejte.

**Windows 10/11** – instalátor `.exe` (instaluje se jen pro aktuálního
uživatele, bez práv správce). SmartScreen ukáže varování, protože instalátor
zatím není podepsaný: *Další informace → Přesto spustit*.

Před instalací porovnejte SHA-256 souboru s `SHA256SUMS-*.txt` z téhož vydání.

**Aktualizace:** od verze 0.1.1 si aplikace sama hlídá nové verze na GitHub
Releases. Když nějaká vyjde, ukáže nahoře banner *Aktualizovat*; stáhne ji,
ověří podpis (Ed25519) a po restartu běží nová verze. Ručně se instaluje jen
první verze s aktualizacemi. Vydání: `git tag -a vX.Y.Z -m "poznámky"` a push
značky (verze v `package.json`, `tauri.conf.json` a `Cargo.toml` musí sedět).

## Vývoj

Potřeba: Rust (verze v `rust-toolchain.toml`), Node.js 22. Na Linuxu navíc
`libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libxdo-dev`.

```sh
cargo test -p antishield-core -p antishield-cli   # testy jádra
cargo run -p antishield-cli -- scan ~/Downloads    # skener z příkazové řádky
cd app && npm ci && npm test                       # testy rozhraní
cd app && npm run tauri dev                        # aplikace v režimu vývoje
cd app && npm run tauri build                      # balíček; potřebuje TAURI_SIGNING_PRIVATE_KEY
```

| Složka | Obsah |
| --- | --- |
| `crates/antishield-core` | engine: podepsaná pravidla, skener, audit, stav komponent |
| `crates/antishield-cli` | příkaz `antishield` (kontrola, self-test, podpis pravidel) |
| `app/src-tauri` | backend aplikace: příkazy pro rozhraní, nativní dialog |
| `app/src` | rozhraní (React, TypeScript) |
| `rules` | testovací sada pravidel, podpis a veřejný klíč |

## Bezpečnost

- Sada pravidel je podepsaná Ed25519; engine ověří podpis dřív, než obsah
  přečte. Testovacím klíčem `hh-test-2026-10` smí být podepsaná jen testovací
  sada. Soukromé klíče nikdy nepatří do repozitáře ani na Vercel.
- Testy používají jen neškodné vzorky (EICAR, syntetická data, značky).
  Skutečný malware do repozitáře nepatří.
- Rozhraní smí volat jen 8 příkazů povolených v
  `app/src-tauri/capabilities/default.json`; cesty ke kontrole vybírá nativní
  dialog v backendu. App Sandbox je vypnutý, protože aplikace v sandboxu se
  nemůže sama aktualizovat; aktualizace přijme jen s platným podpisem.
- Auditní log je řetězený SHA-256 (`antishield audit verify`).

Zranitelnost hlaste přímo vývojovému týmu H&H, ne veřejným issue.

## Licence

Proprietární software H&H, viz [LICENSE](LICENSE). Knihovny třetích stran
mají vlastní licence (MIT, Apache-2.0, BSD-3-Clause, OFL a další); politiku
hlídá `cargo deny` podle `deny.toml`.
