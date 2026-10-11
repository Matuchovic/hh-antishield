# PROJECT_STATUS – H&H AntiShield

Aktualizováno: 2026-10-11 (v0.1.1)

## Stav
v0.1.1 vydána: https://github.com/Matuchovic/hh-antishield/releases/tag/v0.1.1
(DMG universal, Windows NSIS, podepsané aktualizace, latest.json). PR #1
sloučený do `main`. Aplikace hledá aktualizace po startu, každých 5 min
a při návratu do okna; instalace přes banner po potvrzení uživatele.
Rozhraní podle mockupu (logo H&H Security, animace, pravdivý obsah).
DMG 0.1.0 ověřen na skutečném Macu (okno, self-test).

## Architektura
- `crates/antishield-core` – engine: pravidla podepsaná Ed25519, streamový
  matcher (SHA-256, bajtové vzory, EICAR), bezpečný skener, audit s řetězením
  SHA-256, stav komponent, self-test.
- `crates/antishield-cli` – `antishield` (scan, selftest, rules, audit verify).
- `app/` – Tauri 2 + React; 8 povolených příkazů, přísná CSP, App Sandbox.

## Rozhodnutí
- Tauri místo nativního SwiftUI; jedna aplikace pro macOS a Windows.
- Distribuce bez App Store: DMG z webu (ad-hoc podpis, jednou „Přesto
  otevřít“), Windows NSIS pro aktuálního uživatele (nepodepsaný).
- Samostatný projekt: žádný vliv na hhsecurity a hhcloud.
- Bundle ID `cz.hh.antishield` (dočasné), macOS min. 12.0.
- Aktualizace přes banner (tauri-plugin-updater, podpis Ed25519, GitHub Releases,
  `latest.json`); App Sandbox kvůli tomu vypnutý (rozhodl uživatel 2026-10-11).
  Soukromý klíč updateru jen v GitHub Secrets `TAURI_SIGNING_*` + záloha u uživatele.

## Testy (2026-10-11)
CI: 48 testů jádra na Linuxu, macOS a Windows, clippy `-D warnings`, rustfmt,
cargo deny, testy a build UI, překlad aplikace. Release: kontrola podpisu
a entitlements DMG, self-test aplikace na macOS i Windows. Lokálně navíc
spuštění aplikace pod Xvfb.

## Známé problémy
- Aplikace zatím nespuštěna na skutečném Windows.
- Repozitář je veřejný – zvážit přepnutí na soukromý.
- Artefakty z Actions nejdou stáhnout z cloudového prostředí Claude (blob storage blokovaná).
- Archivy se nerozbalují (jen se započítají).
- Balíčky nejsou podepsané Developer ID ani pro Windows.
- Architektonický dokument (Claude Docs) ještě popisuje nativní variantu.
- Soukromý testovací klíč `hh-test-2026-10` je jen v dočasném úložišti
  session; při ztrátě vygenerovat nový a vyměnit veřejný klíč v `rules/keys`.

## Vydání
Zvýšit verzi (`app/package.json`, `tauri.conf.json`, `Cargo.toml`), sloučit
do `main`, pak Actions → Release → Run workflow se zaškrtnutým „publish“.
Vydání potvrzuje vždy člověk; tag z cloudového prostředí vytvořit nejde.

## Další krok
Nainstalovat 0.1.1 na Macy ručně, pak vydat 0.1.2 a ověřit celý průběh
aktualizace přes banner.
