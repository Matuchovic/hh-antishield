# PROJECT_STATUS – H&H AntiShield

Aktualizováno: 2026-10-11 (v0.2.0, PR čeká na CI a sloučení)

## Stav
- v0.1.1 a v0.1.2 vydány (GitHub Releases, podepsané aktualizace přes banner).
- v0.2.0 hotová ve větvi `claude/v0.2-detection`: YARA-X a produkční pravidla
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
- Pravidla: YARA Forge core, jen licence MIT/Apache/BSD/DRL/CC0/CC-BY/
  Unlicense; podpis klíčem `hh-rules-2026-10` (secret `RULES_SIGNING_KEY`),
  vydání `rules` (prerelease, ne „latest“).
- Animace jen transform/opacity, bez filtru blur a bez `will-change` na
  animovaných vrstvách (rozmazaný rastr ve WebView2), pauza při skrytém okně.

## Testy (2026-10-11, lokálně)
- Rust: 74 testů (jádro 65, CLI 4, aplikace 5), clippy `-D warnings`,
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
- Aplikace zatím nespuštěna na skutečném Windows; 0.2 ani na Macu.
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
Zelené CI v PR → sloučit → secret `RULES_SIGNING_KEY` → Rules (publish) →
Release 0.2.0 (publish) → ověřit na Macu aktualizaci přes banner, hlídání
Stažených souborů (EICAR) a vyčištění.
