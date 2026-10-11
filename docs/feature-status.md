# Stav funkcí – v0.1

Platí pravidlo: aplikace nikdy netvrdí, že počítač chrání, pokud příslušná
komponenta neběží a není ověřená. V0.1 proto hlásí „Ruční kontrola je
připravená“, nikoli „Chráněno“.

## Hotovo a ověřeno testy

| Funkce | Ověření |
| --- | --- |
| Ruční kontrola vybraných souborů a složek | integrační testy `scan.rs`, smoke test CLI |
| SHA-256 indikátory, bajtové vzory přes hranice bloků, standardní EICAR | `matcher.rs` (proptest), `selftest` |
| Podepsaná sada pravidel (Ed25519, verze, platnost, testovací klíč jen pro testovací sadu) | `rules.rs` |
| Bezpečné procházení: bez následování odkazů, jiné disky, FIFO/sokety, hardlinky, hluboké cesty, soubory > 4 GiB | `scan.rs` |
| Průběh, zrušení (do 2 s), zaseknuté čtení (watchdog), izolace pádů na soubor | `scan.rs` |
| Vysvětlené nálezy (pravidlo, důkaz, závažnost, testovací příznak) | `scan.rs`, rozhraní |
| Auditní log s řetězením SHA-256, rotací a ověřením | `audit.rs` |
| Pravdivý souhrn stavu (tabulka všech kombinací) | unit testy `status.rs`, `format.test.ts` |
| Self-test enginu při startu a na vyžádání | `engine.rs`, `--self-test` |
| Aplikace Tauri: přehled, kontrola, výsledky, události, o aplikaci | překlad + spuštění na Linuxu (Xvfb) |

## Částečně

| Funkce | Co chybí |
| --- | --- |
| Cesty delší než 1024 B na macOS | systém je neumí otevřít; skener je hlásí jako přeskočené (chyba čtení) |
| Archivy (ZIP, DMG, …) | rozpoznají se a započítají jako „nerozbalené“, obsah se nekontroluje |
| macOS a Windows specifika (O_NOFOLLOW_ANY, dataless soubory, reparse points) | testy prošly v CI na macOS i Windows; chybí ruční test na skutečném zařízení |
| App Sandbox na macOS | entitlements nastavené, chování ověřit na skutečném Macu |
| Distribuce | DMG podepsaný ad-hoc, Windows nepodepsaný; uživatel musí jednou povolit spuštění |

## Chybí (plánováno)

Ochrana v reálném čase, karanténa, aktualizace pravidel, internetová ochrana,
ochrana e-mailů a soukromí, System Care, podpis Developer ID + notarizace,
podpis pro Windows, automatické aktualizace aplikace, produkční sada pravidel
a produkční podpisový klíč, úplný seznam licencí v balíčku.
