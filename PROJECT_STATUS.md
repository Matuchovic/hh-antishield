# PROJECT_STATUS – H&H AntiShield

Aktualizováno: 2026-10-11 (v0.3.0)

## Stav
- v0.1.1, v0.1.2 a v0.2.0 vydány; první produkční sada pravidel zveřejněna
  (vydání `rules`).
- v0.2.0 na macOS padá hned po startu: tvrzené prostředí ukončí vlákno
  enginu, když YARA-X spustí kód přeložený za běhu („Code Signature
  Invalid“). Opraveno ve v0.2.1 (výjimka `allow-unsigned-executable-memory`);
  0.2.0 se sama aktualizovat nestihne, 0.2.1 je potřeba nainstalovat z DMG.
- v0.3.0: hlídání spuštěných programů (každé 3 s; jistý nález = ukončit
  a izolovat, méně jistý = nahlásit), hlídání položek po přihlášení i s jejich
  programem, tlačítka do Nastavení systému u vypnutých ochran.
- v0.2.2 (součást 0.3.0): ochrana běží na pozadí i po zavření/ukončení aplikace (macOS
  LaunchAgent s KeepAlive, vypnutí jen z lišty s potvrzením, ochrana proti
  smyčce pádů) a po spuštění dožene kontrolu souborů, které přibyly, když
  neběžela.
- v0.2: YARA-X a produkční pravidla
  z YARA Forge, ZIP, hlídání složek v reálném čase, karanténa a vyčištění
  (proces, položka po přihlášení), rychlá/úplná/plánovaná kontrola, bezpečnost
  systému (jen čtení), nastavení, lišta, spuštění po přihlášení, oznámení,
  animované jádro, úvodní znělka a zvuky.
- Úroveň „hlídaný“ (Monitored) jen při běžícím hlídání a čerstvých
  pravidlech; „Chráněno“ zatím nedosažitelné (chybí blokování spouštění).

## Architektura
- `crates/antishield-core` – engine: podepsaná pravidla (SHA-256, vzory,
  YARA-X v namespacích s licencí), skener se ZIP, karanténa, náprava, hlídání
  složek, procesy a položky po spuštění, stav systému, audit, self-test.
- `crates/antishield-cli` – `antishield` (scan, selftest, rules build/sign/
  verify, audit verify).
- `app/` – Tauri 2 + React; 21 povolených příkazů, přísná CSP, služby na
  pozadí (hlídání, pravidla po 6 h, plánovač), lišta, single-instance.

## Rozhodnutí
- Tauri, jedna aplikace pro macOS a Windows; distribuce mimo App Store.
- Samostatný projekt: žádný vliv na hhsecurity a hhcloud.
- Aktualizace aplikace přes banner (GitHub Releases), App Sandbox vypnutý.
- Ochrana na pozadí na macOS: vlastní LaunchAgent `cz.hh.antishield.agent`
  (RunAtLoad, KeepAlive, ThrottleInterval 10 s) místo pluginu autostart;
  jen pro aplikaci nainstalovanou v Aplikacích. Na Windows dál plugin
  (spuštění po přihlášení, bez obnovy po ukončení).
- Tvrzené prostředí (hardened runtime) zapnuté s jedinou výjimkou
  `com.apple.security.cs.allow-unsigned-executable-memory` pro JIT ve
  wasmtime (YARA-X); Release spouští self-test z podepsaného balíčku.
- Pravidla: YARA Forge core, jen licence MIT/Apache/BSD/DRL/CC0/CC-BY/
  Unlicense; podpis klíčem `hh-rules-2026-10` (secret `RULES_SIGNING_KEY`),
  vydání `rules` (prerelease, ne „latest“).
- Otisky z MalwareBazaar (abuse.ch) nepoužity: export vyžaduje Auth-Key
  a komerční použití jen s placeným předplatným Spamhaus (podmínky abuse.ch,
  oddíl 4 a 7.3). Detekce dál z YARA Forge core (licence pro komerční použití).
- Animace jen transform/opacity, bez filtru blur a bez `will-change` na
  animovaných vrstvách (rozmazaný rastr ve WebView2), pauza při skrytém okně.

## Testy (2026-10-11, lokálně)
- Rust: 82 testů (jádro 68, CLI 4, aplikace 10), clippy `-D warnings`,
  rustfmt; self-test aplikace `--self-test` prošel.
- Produkční řetězec pravidel lokálně: build → podpis produkčním klíčem →
  verify → self-test → nález pravidlem z Forge. Odhalil chybu: `rules sign`
  kontroloval podpis jako testovací klíč (opraveno + testy).
- UI: 10 testů vitest, typecheck, build; snímky všech obrazovek v Chromiu
  s náhradou IPC; skutečná aplikace pod Xvfb (WebKitGTK) vykreslí přehled.
- CI v PR #3: jádro zelené na Linuxu, macOS i Windows (macOS odhalil
  odmítnutí cest přes `/var` → `/private/var` při kontrole jednoho souboru;
  opraveno + test).
- Na macOS se při prvním spuštění zeptá systém na přístup ke Staženým
  souborům, Ploše a Dokumentům; bez povolení aplikace hlásí omezené hlídání.

## Známé problémy
- Aplikace zatím nespuštěna na skutečném Windows.
- Self-test v Release dřív běžel na binárce mimo podepsaný balíček, takže
  pád v tvrzeném prostředí neodhalil (opraveno).
- Repozitář je veřejný – zvážit přepnutí na soukromý.
- Z cloudového prostředí nejde stahovat artefakty, tagovat ani nastavit secrets.
- Balíčky nejsou podepsané Developer ID ani pro Windows.
- Architektonický dokument (Claude Docs) ještě popisuje nativní variantu.
- Soukromé klíče `hh-test-2026-10` a `hh-rules-2026-10` jsou jen v dočasném
  úložišti session; produkční patří do GitHub Secrets + záloha u uživatele.

## Vydání
Zvýšit verzi (`app/package.json`, `tauri.conf.json`, `Cargo.toml`), sloučit
do `main`, pak Actions → Release → Run workflow se zaškrtnutým „publish“.
Pravidla: Actions → Rules → Run workflow s „publish“ (jinak každé pondělí).

## Další krok
Sloučit PR s 0.3.0 → Release (publish) → na Macu ověřit: ochrana běží po ⌘Q
i po odhlášení, EICAR ve Stažených souborech zachycen i po vypnutí a zapnutí,
další aktualizace přes banner.
