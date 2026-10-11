# PROJECT_STATUS – H&H AntiShield

Aktualizováno: 2026-10-11

## Stav
v0.1 (ruční skener) implementována a lokálně ověřena. Kód je jen lokálně,
push na GitHub vrací 403 (Claude GitHub App nemá přístup k repozitáři).

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
- Entitlement `network.client` jen kvůli WKWebView v sandboxu; ověřit na Macu.

## Testy (poslední běh 2026-10-10, Linux)
48 testů jádra, 6 testů UI, tsc, clippy `-D warnings`, rustfmt, cargo deny,
`antishield-app --self-test`, spuštění aplikace pod Xvfb – vše prošlo.

## Známé problémy
- Kód pro macOS/Windows zatím nepřeložen (ověří CI), sandbox neověřen na Macu.
- Archivy se nerozbalují (jen se započítají).
- Balíčky nejsou podepsané Developer ID ani pro Windows.
- Architektonický dokument (Claude Docs) ještě popisuje nativní variantu.
- Soukromý testovací klíč `hh-test-2026-10` je jen v dočasném úložišti
  session; při ztrátě vygenerovat nový a vyměnit veřejný klíč v `rules/keys`.

## Další krok
Přístup Claude GitHub App k `Matuchovic/hh-antishield` → push, PR, CI,
workflow Release (DMG + exe).
