# Stav funkcí – v0.2

Platí pravidlo: aplikace nikdy netvrdí ochranu, kterou nemá. V0.2 hlásí
„Váš Mac je hlídaný“, jen když skutečně běží hlídání složek i ověřené
aktualizace pravidel; jinak „Ruční kontrola je připravená“ s důvodem.
Spouštění programů zatím neblokuje, proto nikdy neukáže „Chráněno“.

## Hotovo a ověřeno testy

| Funkce | Ověření |
| --- | --- |
| Kontrola: rychlá (Stažené soubory, Plocha, běžící programy, položky po přihlášení), úplná (domovská složka a aplikace), vlastní | `scan.rs`, CLI, rozhraní |
| Detekce: SHA-256, bajtové vzory přes hranice bloků, EICAR, pravidla YARA (YARA-X) | `matcher.rs`, `scan.rs`, self-test |
| Produkční sada pravidel z YARA Forge core, jen licence vhodné ke komerčnímu použití | `forge.rs`; řetězec sestavení → podpis → ověření → self-test → nález ověřen lokálně produkčním klíčem |
| Aktualizace pravidel: podpis Ed25519, ochrana proti starší verzi, self-test před instalací, návrat k zabudované sadě | `engine.rs` |
| ZIP v paměti s limity (položky, velikost, poměr komprese); vnořené a šifrované archivy se označí | `scan.rs` |
| Karanténa: kontrola otisku a identity souboru, znehodnocení obsahu, obnova bez přepisu, smazání | `engine.rs` |
| Vyčištění souboru jedním kliknutím (do karantény) | `engine.rs`, rozhraní |
| Hlídání složek v reálném čase: nové a změněné soubory, částečná stahování se ignorují | test hlídání v CI (Linux, macOS, Windows) |
| Odepřený přístup ke složce (macOS Soubory a složky) se hlásí jako omezené hlídání s radou, jak ho povolit | unit test `state.rs` |
| Plánovaná kontrola denně / týdně, zmeškaná doběhne po spuštění | unit testy `services.rs` |
| Nastavení (ochrana, karanténa, oznámení, plán, aktualizace, spouštění, zvuk a animace) | unit test `settings.rs`, rozhraní |
| Auditní log s řetězením SHA-256, pravdivý souhrn stavu, self-test | `audit.rs`, `status.rs`, `format.test.ts` |
| Aktualizace aplikace přes banner (podpis, GitHub Releases) | vydání 0.1.1 a 0.1.2 |

## Částečně

| Funkce | Co chybí |
| --- | --- |
| Ukončení škodlivého procesu a vypnutí položky po přihlášení | implementováno; chybí ruční test na skutečném Macu a Windows |
| Bezpečnost systému (Gatekeeper, SIP, FileVault, firewall, XProtect; na Windows Defender a firewall) | jen čte stav a radí, nic nemění; přeloženo v CI, chybí ověření na zařízení |
| Oznámení, ikona v liště, spuštění po přihlášení | přeloženo v CI pro macOS i Windows; chybí ruční test |
| Animace a plynulost | animují se jen transformace a průhlednost, bez rozmazání v pohyblivých vrstvách; ověřeno v Chromiu (jádro WebView2) a WebKitGTK, na Macu ověří uživatel |
| Cesty delší než 1024 B na macOS | systém je neumí otevřít; skener je hlásí jako přeskočené |
| Jiné archivy než ZIP (DMG, PKG, RAR, 7z) | rozpoznají se a započítají jako „nerozbalené“ |
| App Sandbox na macOS | vypnutý kvůli aktualizacím (sandboxovaná aplikace nesmí přepsat sama sebe); tvrzené prostředí zapnuté s výjimkou pro kód YARA-X překládaný za běhu |
| Distribuce | DMG podepsaný ad-hoc, Windows nepodepsaný; uživatel jednou povolí spuštění |

## Chybí (plánováno)

Blokování spouštění programů (macOS Endpoint Security vyžaduje entitlement od
Applu), internetová ochrana, ochrana e-mailů a soukromí, podpis Developer ID
a notarizace, podpis pro Windows.
