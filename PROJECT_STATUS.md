# PROJECT_STATUS – H&H AntiShield

Aktualizováno: 2026-10-11

## Stav
v0.1 (ruční skener) hotová. Kód v PR #1 (větev `claude/v0.1-manual-scanner`),
CI zelené na Linuxu, macOS i Windows. Release běh 38115958371 sestavil DMG
i Windows instalátor (artefakty, self-test prošel).

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

## Testy (2026-10-11)
CI: 48 testů jádra na Linuxu, macOS a Windows, clippy `-D warnings`, rustfmt,
cargo deny, testy a build UI, překlad aplikace. Release: kontrola podpisu
a entitlements DMG, self-test aplikace na macOS i Windows. Lokálně navíc
spuštění aplikace pod Xvfb.

## Známé problémy
- Aplikace zatím nespuštěna na skutečném Macu ani Windows (sandbox, okno).
- Repozitář je veřejný – zvážit přepnutí na soukromý.
- Artefakty z Actions nejdou stáhnout z cloudového prostředí Claude (blob storage blokovaná).
- Archivy se nerozbalují (jen se započítají).
- Balíčky nejsou podepsané Developer ID ani pro Windows.
- Architektonický dokument (Claude Docs) ještě popisuje nativní variantu.
- Soukromý testovací klíč `hh-test-2026-10` je jen v dočasném úložišti
  session; při ztrátě vygenerovat nový a vyměnit veřejný klíč v `rules/keys`.

## Další krok
Ruční test DMG na jednom Macu, pak sloučit PR #1.
