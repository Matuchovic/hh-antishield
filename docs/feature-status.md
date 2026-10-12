# Stav funkcí – v0.7

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
| macOS: obsah instalačních balíčků (PKG, `pkgutil`) a obrazů disků (DMG, připojení jen pro čtení bez Finderu); nález izoluje celý balíček | test na macOS v CI (PKG i DMG s EICAR, nic nezůstane připojené) |
| Rozšíření prohlížečů (Chrome, Edge, Brave, Firefox) v rychlé kontrole | `system.rs` |
| Karanténa: kontrola otisku a identity souboru, znehodnocení obsahu, obnova bez přepisu, smazání | `engine.rs` |
| Vyčištění souboru jedním kliknutím (do karantény) | `engine.rs`, rozhraní |
| Hlídání složek v reálném čase: nové a změněné soubory, částečná stahování se ignorují | test hlídání v CI (Linux, macOS, Windows) |
| Odepřený přístup ke složce (macOS Soubory a složky) se hlásí jako omezené hlídání s radou, jak ho povolit | unit test `state.rs` |
| Kontrola po spuštění: soubory, které v hlídaných složkách přibyly, když AntiShield neběžel | unit testy `watch.rs`, `services.rs` |
| Hlídání spuštěných programů: nový program (mimo systémové) se zkontroluje do ~3 s; jistě škodlivý (vysoká závažnost) se ukončí a izoluje, méně jistý se nahlásí | unit testy `system.rs` (nový proces se nahlásí jednou), `services.rs` (pravidla zásahu) |
| Hlídání položek po přihlášení (LaunchAgents/LaunchDaemons, Windows Startup): nová položka se zkontroluje i s programem, který spouští | `system.rs`, `services.rs`; na Macu ověří uživatel |
| Bezpečnost systému: tlačítko otevře příslušný panel Nastavení systému / Zabezpečení Windows (pevné adresy, nic nemění) | překlad v CI; na zařízení ověří uživatel |
| Ochrana e-mailů (macOS): s plným přístupem k disku hlídá přílohy Apple Mail (Attachments, Mail Downloads); zprávy a indexy přeskakuje | `system.rs`; na Macu ověří uživatel |
| Ochrana soukromí (macOS): přehled aplikací s přístupem k obrazovce, zpřístupnění, sledování vstupu, plnému přístupu k disku, kameře a mikrofonu (TCC jen pro čtení); upozornění na nové citlivé oprávnění | `privacy.rs` (rozbor, nová oprávnění); na Macu ověří uživatel |
| Ochrana na pozadí (macOS): LaunchAgent spustí AntiShield po přihlášení a obnoví ho po ukončení; ⌘Q a zavření okna ji nevypnou, vypnout jde jen z lišty | unit testy `agent.rs`; launchd ověří uživatel na Macu |
| Plánovaná kontrola denně / týdně, zmeškaná doběhne po spuštění | unit testy `services.rs` |
| Nastavení (ochrana, karanténa, oznámení, plán, aktualizace, spouštění, zvuk a animace) | unit test `settings.rs`, rozhraní |
| Auditní log s řetězením SHA-256, pravdivý souhrn stavu, self-test | `audit.rs`, `status.rs`, `format.test.ts` |
| Audit: zapisuje jen jeden proces (zámek); poškozený soubor se uzavře a problém se ohlásí jednou se srozumitelným popisem | unit testy `audit.rs`, `tests/audit.rs`, `format.test.ts` |
| Žádost o plný přístup k disku při spuštění (macOS): panel Nastavení, pozná povolení do 5 s, nabídne restart | průchod v Chromiu s náhradou IPC; na Macu ověří uživatel |
| Jen jedna instance AntiShieldu na macOS (agent počká, ruční spuštění předá okno) | unit testy `instance.rs`; launchd ověří uživatel |
| Poslední kontrola po restartu; nález z ní se před vyčištěním znovu ověří | unit testy `state.rs` |
| Radar ochrany: skutečně zkontrolované položky z hlídání (stažené, soubory, přílohy, programy, položky po přihlášení), počty a živý přehled; při kontrole i procházené soubory | unit testy `story.rs` (počty, pásma); průchod v Chromiu; na Macu ověří uživatel |
| Příběh útoku: původ (adresa, stránka, prohlížeč, odesílatel e-mailu), kdo program spustil, zachycení, zásah, doporučení; uložený jen k zobrazení | unit testy `provenance.rs`, `story.rs`, `story.test.ts`; metadata macOS ověří uživatel |
| Čištění: mezipaměti aplikací, staré protokoly, vývojářské mezipaměti, staré instalátory, zbytky po odinstalovaných aplikacích, velké staré soubory, Koš; jen v domovské složce (bez složek synchronizovaných s cloudem), zásah jen podle vlastního skenu s novým ověřením cesty (bez odkazů), soubory uživatele do Koše, vysypání Koše zvlášť po potvrzení; běžící a právě používané mezipaměti se nepředvybírají; zápis do auditu | unit testy `cleanup.rs` (podvržená a přesunutá položka, odkazy, nainstalované aplikace, cloudové složky), `care.test.ts`; Koš přes systém a skutečný Mac ověří uživatel |
| Zrychlení: volné místo, tlak na paměť (macOS), odkládání na disk, procesor, doba běhu; doporučení jen z naměřených hodnot | unit testy `speed.rs`, `care.test.ts` |
| Náročné aplikace (i s pomocnými procesy) a jejich šetrné ukončení: Apple Event „quit“ jako ⌘Q, SIGTERM, na Windows zavření oken; nikdy násilím, systémové programy ani AntiShield ne, ověření PID | unit testy `speed.rs` (SIGTERM s potvrzením konce, odmítnutí systémových programů a sebe); Apple Events ověří uživatel na Macu |
| Položky po přihlášení: vratné vypnutí a zapnutí uživatelských položek (odloží se do složky aplikace), vlastní agent AntiShieldu nejde vypnout; systémové položky jen s odkazem do Nastavení systému | unit test `speed.rs`; launchctl ověří uživatel na Macu |
| Aktualizace aplikace přes banner (podpis, GitHub Releases) | vydání 0.1.1 a 0.1.2 |

## Částečně

| Funkce | Co chybí |
| --- | --- |
| Ukončení škodlivého procesu a vypnutí položky po přihlášení | implementováno; chybí ruční test na skutečném Macu a Windows |
| Bezpečnost systému (Gatekeeper, SIP, FileVault, firewall, XProtect; na Windows Defender a firewall) | jen čte stav a radí, nic nemění; přeloženo v CI, chybí ověření na zařízení |
| Oznámení, ikona v liště, spuštění po přihlášení | přeloženo v CI pro macOS i Windows; chybí ruční test |
| Animace a plynulost | animují se jen transformace a průhlednost, bez rozmazání v pohyblivých vrstvách; ověřeno v Chromiu (jádro WebView2) a WebKitGTK, na Macu ověří uživatel |
| Firemní správa: správce vidí firemní Macy (ochrana, hrozby, disk, paměť, kolik jde uklidit) a posílá podepsané příkazy (kontrola, izolace hrozeb, úklid podle kategorií); Macy připojené kódem pozvánky, souhlas uživatele u instalátorů a zbytků, soubory uživatele a Koš nikdy | implementováno, testy protokolu se schránkou v paměti a samotest schránky v SQL; schránka na serveru nasazená zčásti (funkce s mazáním čekají na potvrzení); na skutečných Macích neověřeno |
| Cesty delší než 1024 B na macOS | systém je neumí otevřít; skener je hlásí jako přeskočené |
| Archivy RAR, 7z, gzip a vnořené archivy | rozpoznají se a započítají jako „nerozbalené“ (DMG a PKG se na macOS kontrolují) |
| App Sandbox na macOS | vypnutý kvůli aktualizacím (sandboxovaná aplikace nesmí přepsat sama sebe); tvrzené prostředí zapnuté s výjimkou pro kód YARA-X překládaný za běhu |
| Distribuce | DMG podepsaný ad-hoc, Windows nepodepsaný; uživatel jednou povolí spuštění |

## Chybí (plánováno)

Hlídání nebezpečného chování programů (posloupnosti akcí typických pro
nejhorší škodlivý software); blokování spouštění programů předem (macOS Endpoint Security vyžaduje
entitlement od Applu a Developer ID; dnes se škodlivý program ukončí až po
spuštění), internetová ochrana (blokování webů vyžaduje Network Extension
od Applu), ochrana e-mailů mimo Apple Mail, ochrana soukromí na Windows,
podpis Developer ID a notarizace, podpis pro Windows, ochrana na pozadí
s obnovou po ukončení i na Windows.
