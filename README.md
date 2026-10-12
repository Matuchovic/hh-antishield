# H&H AntiShield

Desktopová aplikace pro macOS a Windows (Tauri 2 + Rust). Verze **0.7**
kontroluje soubory pravidly YARA a otisky (včetně obsahu ZIP a na macOS
balíčků PKG a obrazů DMG), na pozadí hlídá vybrané složky, nově spuštěné
programy, položky po přihlášení a přílohy Apple Mail, nálezy izoluje do
karantény (škodlivý proces ukončí, položku po přihlášení vypne), ukáže
oprávnění aplikací (obrazovka, klávesnice, kamera, …) a upozorní na nová,
sama si aktualizuje podepsaná pravidla i aplikaci. Radar ochrany ukazuje
živě, co hlídání právě kontroluje, a ke každé hrozbě je příběh útoku: odkud
přišla, co ji spustilo a co AntiShield udělal. Čištění najde, co v domovské
složce zbytečně zabírá místo (mezipaměti, staré protokoly a instalátory,
zbytky po aplikacích, velké staré soubory), a uklidí jen to, co potvrdíte;
soubory uživatele přesouvá do Koše. Zrychlení změří disk, paměť, procesor
a dobu běhu, ukáže náročné aplikace (ukončí je jen šetrně, jako ⌘Q)
a položky po přihlášení vratně vypne. Firemní správa dovolí správci (CTO)
vidět firemní Macy a na dálku je zkontrolovat, izolovat hrozby a uklidit;
příkazy jsou podepsané, zprávy šifrované a server mezi nimi je jen schránka
(podrobnosti v [relay/README.md](relay/README.md)). Spouštění programů předem
neblokuje a internetovou ochranu zatím nemá; aplikace to otevřeně říká.
Přesný stav je v [docs/feature-status.md](docs/feature-status.md).

Projekt je samostatný: nesdílí kód, účty, klíče ani nasazení s hhsecurity
ani hhcloud.

## Instalace (bez App Store)

Balíčky jsou ke stažení na
[GitHub Releases](https://github.com/Matuchovic/hh-antishield/releases/latest).

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

**Aktualizace aplikace:** od verze 0.1.1 si aplikace sama hlídá nové verze
(po startu, každých 5 minut a při návratu do okna). Když nějaká vyjde, ukáže
banner *Aktualizovat*; stáhne ji, ověří podpis (Ed25519) a po restartu běží
nová verze. Vydání: zvýšit verzi v `app/package.json`, `tauri.conf.json`
a `Cargo.toml`, sloučit do `main`, pak *Actions → Release → Run workflow*
se zaškrtnutým *publish*.

**Aktualizace pravidel:** workflow *Rules* jednou týdně sestaví sadu z YARA
Forge (jen licence vhodné ke komerčnímu použití), podepíše ji klíčem
`hh-rules-2026-10` (secret `RULES_SIGNING_KEY`), ověří self-testem a bez
falešných poplachů na čistém macOS a zveřejní ji ve vydání `rules`. Aplikace
ji stahuje každých 6 hodin a nainstaluje jen platně podepsanou novější sadu.

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
| `app/src-tauri` | backend aplikace: příkazy pro rozhraní, hlídání, plánování, lišta |
| `app/src` | rozhraní (React, TypeScript) |
| `rules` | základ produkční sady, testovací sada, self-test YARA, veřejné klíče |

## Bezpečnost

- Sada pravidel je podepsaná Ed25519; engine ověří podpis dřív, než obsah
  přečte, odmítne starší sadu a novou nasadí jen po úspěšném self-testu.
  Testovacím klíčem `hh-test-2026-10` smí být podepsaná jen testovací sada.
  Soukromé klíče nikdy nepatří do repozitáře ani na Vercel.
- Karanténa ověří, že jde o stejný soubor, jaký kontrola našla (otisk
  a identita), obsah znehodnotí a při obnově nic nepřepíše. Proces ukončí
  jen tehdy, když jeho spustitelný soubor je nalezený soubor.
- Bezpečnost systému jen čte stav (Gatekeeper, SIP, FileVault, firewall,
  Defender); aplikace ochrany systému nikdy nevypíná ani nemění.
- Testy používají jen neškodné vzorky (EICAR, syntetická data, značky).
  Skutečný malware do repozitáře nepatří.
- Rozhraní smí volat jen 43 příkazů povolených v
  `app/src-tauri/capabilities/default.json`; cesty ke kontrole vybírá nativní
  dialog v backendu a vyčistit jde jen nález, který backend sám vytvořil nebo právě znovu ověřil.
  Čištění a zrychlení stejně: rozhraní posílá jen identifikátory z posledního
  skenu či měření, jádro cestu a program před zásahem znovu ověří. App Sandbox je vypnutý, protože aplikace v sandboxu se
  nemůže sama aktualizovat; aktualizace přijme jen s platným podpisem.
- Auditní log je řetězený SHA-256 (`antishield audit verify`).

Zranitelnost hlaste přímo vývojovému týmu H&H, ne veřejným issue.

## Licence

Proprietární software H&H, viz [LICENSE](LICENSE). Knihovny třetích stran
mají vlastní licence (MIT, Apache-2.0, BSD-3-Clause, ISC, CC0, OFL a další);
politiku hlídá `cargo deny` podle `deny.toml`. Pravidla YARA mají licence
svých autorů (přehled v aplikaci, *O aplikaci → Zdroje pravidel*).
