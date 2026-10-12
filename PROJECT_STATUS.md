# PROJECT_STATUS – H&H AntiShield

Aktualizováno: 2026-10-12 (v0.8.0 vydána)

## Stav
- v0.8.0 vydána 12. 10. 2026 (PR #13, Release: DMG universal, instalátor
  Windows, `latest.json` pro macOS Intel/Apple Silicon a Windows): rozšířená
  správa firemního Macu. Platí až po souhlasu uživatele Macu: správce
  pošle žádost, uživatel vidí, co by správce navíc viděl a smí (nové
  položky označené), a rozhodne. Zásahy: hloubková údržba (mezipaměti
  aplikací, které neběží, i čerstvé; mezipaměti běžících aplikací až po
  souhlasu se zavřením těch aplikací), Koš a velké staré soubory (vždy jen
  se souhlasem; velké soubory vybírá uživatel a jejich názvy správce
  nevidí), žádost o restart (uživatel může odložit o hodinu nebo do rána),
  návrh ukončit aplikace (uživatel vybere), aktualizace AntiShieldu
  a pravidel na dálku (jen podepsané vydání), úplná kontrola, mazání
  z karantény. Detail Macu u správce má záložky Přehled (celkový stav
  0–100 s důvody, doporučení s akcemi), Údržba, Zabezpečení (FileVault,
  firewall a neviditelný režim, SIP, Gatekeeper, XProtect, automatické
  a čekající aktualizace macOS, Time Machine, plný přístup k disku),
  Výkon (procesor, paměť, odkládání, aplikace podle paměti, položky po
  přihlášení), Hrozby (nálezy, karanténa, časová osa ochrany), Hardware
  (čip, jádra, paměť, sériové číslo, baterie: cykly, kapacita, servis)
  a Historie. Mac 0.7 dál funguje se základní správou; protokol zůstal
  ve verzi 1.
- v0.7.0 vydána 12. 10. 2026 (PR #11, Release: DMG universal, instalátor
  Windows, `latest.json` pro macOS Intel/Apple Silicon a Windows): firemní správa. Správce
  (CTO) na svém Macu vidí firemní Macy na mapě a v seznamu (ochrana,
  hrozby, disk, paměť, kolik jde uklidit) a posílá jim podepsané příkazy:
  kontrola, izolace hrozeb, úklid podle kategorií (i všem najednou).
  Mezipaměti, protokoly a vývojářské mezipaměti hned, staré instalátory
  a zbytky aplikací jen po souhlasu uživatele Macu, soubory uživatele a Koš
  nikdy. Připojení kódem pozvánky; uživatel před připojením vidí, co správce
  uvidí a smí, a otisk jeho klíče; může se kdykoli odpojit. Schránka na
  Supabase (projekt Matucha) je jen přepravník šifrovaných zpráv.
  Schránka je nasazená celá (12. 10. 2026, uživatel spustil
  `relay/migrations/0001_antishield_fleet.sql` v SQL editoru; těla všech
  18 funkcí se shodují s repozitářem).
- v0.1.1, v0.1.2 a v0.2.0 vydány; první produkční sada pravidel zveřejněna
  (vydání `rules`).
- v0.2.0 na macOS padá hned po startu: tvrzené prostředí ukončí vlákno
  enginu, když YARA-X spustí kód přeložený za běhu („Code Signature
  Invalid“). Opraveno ve v0.2.1 (výjimka `allow-unsigned-executable-memory`);
  0.2.0 se sama aktualizovat nestihne, 0.2.1 je potřeba nainstalovat z DMG.
- v0.6.0: Čištění a zrychlení. Čištění hledá v domovské složce mezipaměti,
  staré protokoly, vývojářské mezipaměti, staré instalátory, zbytky po
  aplikacích a velké staré soubory; uklidí jen potvrzené položky z vlastního
  skenu, soubory uživatele do Koše, Koš vysype jen po výslovném potvrzení.
  Zrychlení měří disk, tlak na paměť, odkládání na disk, procesor a dobu běhu,
  ukazuje náročné aplikace se šetrným ukončením a vratně vypíná položky po
  přihlášení. Plátno s jádrem: nalezená data obíhají jako částice podle
  skutečné velikosti a úklid pohltí přesně to, co se uklidilo.
  Hlídání nebezpečného chování programů v 0.6 není.
- v0.5.0: radar ochrany v reálném čase (přehled i obrazovka Ochrana; jen
  skutečně zkontrolované položky, počty, živý přehled), příběh útoku ke každé
  hrozbě (původ souboru, uložení, kdo program spustil, zachycení, zásah,
  doporučení), živější jádro (vrstvy plazmatu, náklon za kurzorem, záblesk
  při hrozbě, záře vrstvy, která kontrolu provedla, úvodní vlna).
- v0.4.1: žádost o plný přístup k disku při spuštění (pozná povolení do 5 s,
  hned přidá hlídání příloh Apple Mail, nabídne restart); auditní log
  s výhradním zámkem a uzavřením poškozeného souboru (problém se hlásí jednou
  a srozumitelně); jen jedna instance na macOS (agent počká, žádná smyčka
  restartů); poslední kontrola přežije restart; oprava dlaždice na přehledu.
- v0.4.0: kontrola obsahu PKG a DMG (macOS), ochrana e-mailových příloh
  Apple Mail a přehled oprávnění aplikací s upozorněním na nové citlivé
  oprávnění (obojí s plným přístupem k disku), rozšíření prohlížečů v rychlé
  kontrole, aktualizace jen z nainstalované aplikace s jasnou chybou (0.3.1).
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
  verify, audit verify, fleet activation).
- `app/` – Tauri 2 + React; 44 povolených příkazů, přísná CSP, služby na
  pozadí (hlídání, pravidla po 6 h, plánovač, firemní správa), lišta,
  single-instance.
- `crates/antishield-core/src/fleet.rs` – protokol firemní správy (klíče,
  podpisy, šifrování, kódy, zásady, příkazy, zprávy, plán hloubkového
  úklidu); `crates/antishield-core/src/inventory.rs` – hardware, baterie,
  zabezpečení a výkon Macu pro zprávu správci; `app/src-tauri/src/
  fleet/` – klient schránky, stav správce a Macu, provedení příkazů;
  `relay/` – SQL schránky a postup pro aktivační kódy.

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
- DMG se připojuje jen pro čtení, bez Finderu, do soukromé dočasné složky
  a hned odpojuje; šifrované obrazy se přeskočí. PKG se rozbalí `pkgutil
  --expand-full`. Limity: 2 GiB PKG / 4 GiB DMG, 20 000 souborů, 2 GiB dat,
  180 s.
- Plný přístup k disku je volitelný: bez něj ochrana e-mailů a soukromí
  hlásí „vyžaduje plný přístup k disku“ a tlačítko otevře správný panel.
  Databáze oprávnění (TCC) se čte jen přes `sqlite3 -readonly`.
- Otisky z MalwareBazaar (abuse.ch) nepoužity: export vyžaduje Auth-Key
  a komerční použití jen s placeným předplatným Spamhaus (podmínky abuse.ch,
  oddíl 4 a 7.3). Detekce dál z YARA Forge core (licence pro komerční použití).
- Audit: výhradní zámek `audit.lock` (zapisuje jen jeden proces); poškozený
  soubor se při otevření uzavře, zápis pokračuje v novém souboru navázaném na
  poslední platný záznam. Incident je jednou v událostech, komponenta Audit
  pak běží normálně; `antishield audit verify` ukazuje historii dál.
- Jedna instance na macOS: zámek `instance.lock` v datech aplikace. Agent
  čeká, až předchozí instance skončí; ruční spuštění po 3 s předá okno běžící
  instanci (plugin single-instance).
- Souhrn poslední kontroly se ukládá (`last-summary.json`) jen k zobrazení;
  nález z minulého spuštění se před vyčištěním znovu zkontroluje.
- Příběh útoku vzniká při nálezu, dřív než se soubor izoluje a proces ukončí
  (původ z metadat stažení: macOS WhereFroms a karanténní značka, Windows
  Zone.Identifier, Linux xdg; nejvýš 64 KB, adresy bez parametrů a údajů).
  Ukládá se (`stories.json`, 100 posledních) jen k zobrazení; o zásahu
  nerozhoduje.
- Radar ukazuje jen skutečné kontroly (žádná vymyšlená aktivita): dávky
  z hlídání s počtem a nejvýš 6 názvy, hrozby vždy. Plátno v nečinnosti
  30 snímků/s, se skrytým oknem a omezením pohybu stojí.
- Animace jen transform/opacity, bez filtru blur a bez `will-change` na
  animovaných vrstvách (rozmazaný rastr ve WebView2), pauza při skrytém okně.
- Čištění: jen domovská složka; mazat (smazat) jde jen to, co si aplikace
  vytvoří znovu (mezipaměti, protokoly starší než týden, vývojářské
  mezipaměti); instalátory, zbytky aplikací, velké soubory a archivy Xcode
  jdou do Koše přes systém (crate `trash`, na macOS NSFileManager, bez
  ovládání Finderu). Mezipaměť změněná v posledních 15 minutách (na Windows
  dočasné soubory za den) a mezipaměť běžící aplikace se nepředvybírá.
  Velké soubory se nehledají ani neuklízejí ve složkách synchronizovaných
  s cloudem (Dropbox, OneDrive, Google Drive, Box, …): Koš by je smazal
  i na ostatních zařízeních.
  Každý zásah znovu ověří umístění podle kategorie a že žádný článek cesty
  není odkaz. Zápis do auditu (`cleanup`).
- Zrychlení: žádné „čištění RAM“ ani zásahy do systému. Ukončení jen šetrné
  (macOS Apple Event „quit“ s `NSAppleEventsUsageDescription` a entitlementem
  `automation.apple-events`; jinak SIGTERM; Windows `taskkill` bez /F).
  Položky po přihlášení se odkládají do `startup-disabled` v datech aplikace
  (`launchctl bootout`/`bootstrap`), vlastní agent nejde vypnout.
- Hlídání nebezpečného chování programů se do 0.6 nedostalo; aplikace ho
  nikde netvrdí.
- Firemní správa: schránka je nedůvěryhodná. Příkazy podepisuje Ed25519 klíč
  správce a šifrují se pro Mac (X25519 + HKDF-SHA256 + ChaCha20-Poly1305,
  nový klíč pro každou zprávu); zprávy Maců podepisuje klíč Macu a šifrují
  se pro správce. Klíče se při připojení svazují HMAC jednorázovým kódem
  pozvánky (120 bitů, schránka zná jen odvozený identifikátor; kontrolní
  znak Luhn mod 32 přes prefix i data pozná každý překlep v jednom znaku,
  záměnu druhu kódu a prohození sousedních znaků kromě 0/Z). Mac přijme
  příkaz jen pro svou firmu a sebe, v platnosti (nejvýš 8 dní, tolerance
  hodin 10 min), poprvé (pamatuje si 30 dní) a nejvýš 30 za hodinu.
- Zásady (co hned, co se souhlasem) se pevně uloží při připojení. Od 0.8
  je rozšíří jen souhlas uživatele Macu se žádostí správce (příkaz
  `policy`; Mac uloží jen to, co správce nabídl a uživatel potvrdil).
  Velké soubory a Koš smí být jen „se souhlasem“, nikdy „hned“ (natvrdo
  v jádru). Úklid na dálku bere jen položky z vlastního čerstvého skenu.
- Rozšířená správa (0.8): restart a ukončení aplikací se uživatele zeptá
  vždy. Hloubkový úklid smaže hned mezipaměti aplikací, které neběží
  (mimo zapsané v posledních 2 min); mezipaměti běžící aplikace (podle
  bundle ID nebo názvu) až po souhlasu se zavřením a jen ty, jejichž
  aplikace pak opravdu neběží. Koš se vysype dřív, než do něj přijdou
  soubory z úklidu (ty jde ještě vrátit). Ukončit jde jen běžící
  aplikace mimo systémové a AntiShield. Odklad restartu 5 min–24 h, nejdéle
  do vypršení žádosti. Restart na macOS přes Finder (Apple Event; poprvé
  se systém zeptá na povolení ovládání Finderu). Aktualizace na dálku
  počká na doběhnutí kontrol, instaluje jen podepsané vydání a jen
  z Aplikací. Ochrany systému (FileVault, firewall…) AntiShield na dálku
  nemění, jen ukáže stav a postup.
- Podrobnosti ve zprávě (0.8) jen podle potvrzených zásad; zpráva se
  vejde do 64 KiB (jinak ubírá události, karanténu, položky po přihlášení,
  nálezy). Položky po přihlášení jen s názvem programu (bez cesty),
  události jen s povolenými poli. Celkový stav 0–100 je součet srážek za
  to, co Mac poslal; bez stavu zabezpečení se označí „Ze základních
  údajů“. Operační paměť v binárních jednotkách jako v macOS.
- Klíče správce i Macu jsou v souborech 0600 (`fleet/admin.json`,
  `fleet/member.json`). Keychain/Secure Enclave by s ad-hoc podpisem po
  každé aktualizaci chtěl heslo; po podpisu Developer ID přesunout.
- Zakládání firem jen s aktivačním kódem (ukládá se SHA-256), aby schránku
  nemohl použít kdokoli s veřejným klíčem z aplikace.
- Mac se hlásí každých ~30 s (po příkazu 5 s), správce obnovuje stav každých
  30 s (po příkazu 3 s); zpráva o stavu každých 15 min a po zásahu, odhad
  úklidu nejvýš dvakrát denně. Oznámení o zásahu správce se ukáže vždy
  (i s vypnutými oznámeními) a zásah jde do auditu.

## Testy (2026-10-12, lokálně)
- 0.8: Rust 139 testů na Linuxu (jádro 103, CLI 2, aplikace 34; 2 živé
  testy schránky zvlášť). Nové: zásady v2 (rozšíření jen souhlasem, Koš
  a velké soubory nikdy „hned“, zpráva z 0.7 = základní zásady), hloubkový
  úklid šetří běžící aplikace, rozbor baterie (Apple Silicon, Intel,
  porucha), čekajících aktualizací, automatických aktualizací a Time
  Machine, výkon bez cest; aplikace: rozšířená správa až po souhlasu,
  podrobnosti podle zásad a do limitu schránky, odložený restart se vrátí
  a vyprší, firma z 0.7 nabídne rozšířenou správu. UI: 37 testů vitest
  (+5: ochrany systému, celkový stav, doporučení podle zásad, nové příkazy,
  binární paměť), typecheck, build; 17 obrazovek v Chromiu s náhradou IPC
  (správce i spravovaný Mac) bez chyb v konzoli. Sběr údajů na macOS
  (sysctl, ioreg, softwareupdate, Time Machine), restart, ukončení
  aplikací a aktualizaci na dálku ověří CI (překlad, clippy) a uživatel na
  skutečném Macu.
- 0.8 CI: v PR #13 zelené na Linuxu, macOS i Windows. Clippy na macOS
  napoprvé odhalil výřez řetězce před `as_bytes` v kódu jen pro macOS
  (`inventory.rs`, ioreg); opraveno. Větve kódu pro macOS se teď dají
  zkontrolovat i lokálně: kopie jádra, kde se `target_os = "macos"`
  přepne na Linux (mimo `platform/`), a clippy s `-D warnings` prošel.
  Release 0.8.0 zelený (DMG se self-testem v podepsaném balíčku,
  instalátor Windows, podepsané archivy pro aktualizaci).
- 0.7: jádro 10 testů firemní správy (kódy, vazba klíčů, podvržené klíče,
  příkazy jen podepsané/pro tento Mac/v platnosti/poprvé/v zásadách,
  soubory uživatele a Koš nikdy, šifrování proti úpravám a záměně druhu
  zprávy, výběr bezpečných položek úklidu, soubory 0600). Aplikace: celá
  cesta správce ↔ Mac přes schránku v paměti (pozvánka, připojení, zpráva,
  úklid se souhlasem, opakované doručení, starší zpráva, odpojení,
  odebrání, podvržený příkaz/klíče/výsledek, zahlcení, vypršení souhlasu),
  tvar JSON ze SQL. UI: 32 testů vitest (+6 firemní správa). Schránka:
  samotest v SQL jako `anon` (neplatná/jednorázová aktivace a pozvánka,
  cizí tokeny, platnost nad 8 dní, žádný přímý přístup k tabulkám),
  vše vráceno. Obrazovky v Chromiu s náhradou IPC bez chyb v konzoli.
- 0.7 schránka: SQL na zkušebním PostgreSQL 16 dvakrát po sobě bez chyby,
  `relay/tests/relay_test.sql` 52/52 jako `anon` (celý životní cyklus,
  opakované doručení po 10 min, limity 50/20, odpojení, odebrání, smazání,
  práva). Klient aplikace proti místnímu PostgREST 12.2.3 se stejným SQL:
  `live_relay_contract` i `live_relay_round_trip` prošly (odhalily, že živé
  testy neinstalovaly poskytovatele TLS – aplikace ho má v `main`, opraveno
  v testech). V Supabase po nasazení kouřový test všech funkcí jako `anon`
  v transakci, která se vrátila; schránka zůstala prázdná. Z kontejneru na
  supabase.co přes HTTP nejde, `live_relay_contract` proto běží v CI
  (poprvé zelený proti skutečné schránce).
- 0.7 kódy: CI jednou spadlo na testu překlepu – kontrolní znak z otisku
  (5 bitů) propustil 1 překlep z 32. Nahrazen Luhnem mod 32; test teď
  zkouší všech 775 jednoznakových překlepů, prohození sousedů a záměnu
  druhu kódu (40 opakování s náhodnými kódy bez chyby).
- Rust: 128 testů na Linuxu (jádro 98, CLI 2, aplikace 28; 2 živé testy
  schránky se spouští zvlášť) + test PKG/DMG jen na macOS, clippy
  `-D warnings`, rustfmt. Nové: čištění (nález
  a úklid, podvržená/přesunutá položka, odkazy, zbytky aplikací, právě
  používaná mezipaměť, složky synchronizované s cloudem), zrychlení (měření, vratné položky po přihlášení,
  SIGTERM s ověřením konce, odmítnutí systémových programů a sebe).
- UI: 32 testů vitest (čištění a zrychlení, firemní správa), typecheck, build.
- 0.6: CI zelené (Linux, macOS, Windows), build-only Release (DMG
  s self-testem v podepsaném balíčku, instalátor Windows) zelený.
- 0.6: obrazovka Čištění a zrychlení v Chromiu s náhradou IPC (hledání
  s průběhem, výsledek, zvýraznění kategorie, položky, úklid s pohlcením
  a selháním jedné položky, potvrzení Koše, měření, ukončení aplikace,
  vypnutí položky po přihlášení); bez chyb v konzoli. Kód jen pro macOS
  a Windows (Koš, Apple Events, launchctl, taskkill) ověří CI a uživatel.
- 0.5: radar a příběh ověřené v Chromiu s náhradou IPC a proudem událostí
  (body, zásah hrozby, živý přehled, Esc, Tab); s omezením pohybu plátno
  stojí. V softwarovém vykreslování kontejneru nejde měřit skutečné snímky;
  čas skriptů s radarem pod 2 % hlavního vlákna.
- 0.4.1: žádost o přístup prošla v Chromiu s náhradou IPC (dotaz, čekání,
  restart, potvrzení, Esc, Tab, okno 1024 × 700); dlaždice bez překryvu
  v 1024, 1400 a 1850 px. Na Macu zatím neověřeno (TCC, launchd, restart).
- Produkční řetězec pravidel lokálně: build → podpis produkčním klíčem →
  verify → self-test → nález pravidlem z Forge. Odhalil chybu: `rules sign`
  kontroloval podpis jako testovací klíč (opraveno + testy).
- UI: 11 testů vitest, typecheck, build; snímky všech obrazovek v Chromiu
  s náhradou IPC; skutečná aplikace pod Xvfb (WebKitGTK) vykreslí přehled.
- CI v PR #3: jádro zelené na Linuxu, macOS i Windows (macOS odhalil
  odmítnutí cest přes `/var` → `/private/var` při kontrole jednoho souboru;
  opraveno + test).
- Na macOS se při prvním spuštění zeptá systém na přístup ke Staženým
  souborům, Ploše a Dokumentům; bez povolení aplikace hlásí omezené hlídání.

## Známé problémy
- Aktualizace přes banner selže, když aplikace neběží ze složky Aplikace
  (spuštěná z DMG nebo ze Stažených – macOS ji přesune do dočasného umístění
  jen pro čtení). Od 0.3.1 to banner řekne i s postupem; 0.3.0 je potřeba
  jednou nainstalovat ručně do Aplikací.
- Aplikace zatím nespuštěna na skutečném Windows.
- Self-test v Release dřív běžel na binárce mimo podepsaný balíček, takže
  pád v tvrzeném prostředí neodhalil (opraveno).
- Repozitář je veřejný – zvážit přepnutí na soukromý.
- Z cloudového prostředí nejde stahovat artefakty, tagovat ani nastavit secrets.
- Balíčky nejsou podepsané Developer ID ani pro Windows. S ad-hoc podpisem
  macOS po aktualizaci obvykle zapomene udělená oprávnění (plný přístup,
  složky); žádost o přístup proto radí přepínač vypnout a zapnout.
- Architektonický dokument (Claude Docs) ještě popisuje nativní variantu.
- Tajnou proměnnou `ANTISHIELD_FLEET_ACTIVATION` (celá cesta proti živé
  schránce v CI) z cloudu nastavit nejde; nastaví uživatel (volitelné,
  smlouva se schránkou běží v CI i bez ní).
- Poradce zabezpečení Supabase u schránky hlásí „RLS bez politik“ (tabulky
  jsou záměrně bez přístupu) a „SECURITY DEFINER volatelná rolí anon“
  (záměr: funkce jsou API schránky a samy ověřují tokeny).
- Aktivační kód pro správce je vydaný (jednorázový, platí do 11. 11. 2026,
  předaný uživateli v chatu; v repozitáři není). První kód (`…5AGD7`) měl
  kontrolní znak podle starého otisku; je zneplatněný (`uses_left = 0`)
  a nahrazený novým (otisk `43f8ab42…`).
- 0.8 na skutečném Macu neověřena. Mac Viktórie Ladikové běží na 0.7.0:
  aktualizuje se přes banner v aplikaci (0.7 aktualizaci na dálku neumí)
  a uživatelka pak musí potvrdit rozšířenou správu; do té doby jde jen
  základní správa.
- Soukromé klíče `hh-test-2026-10` a `hh-rules-2026-10` jsou jen v dočasném
  úložišti session; produkční patří do GitHub Secrets + záloha u uživatele.

## Vydání
Zvýšit verzi (`app/package.json`, `tauri.conf.json`, `Cargo.toml`), sloučit
do `main`, pak Actions → Release → Run workflow se zaškrtnutým „publish“.
Pravidla: Actions → Rules → Run workflow s „publish“ (jinak každé pondělí).

## Další krok
Správce i Mac Viktórie aktualizovat na 0.8 (banner), správce požádá
o rozšířenou správu, uživatelka potvrdí. Pak ověřit detail (hardware,
zabezpečení, výkon), hloubkovou údržbu, žádost o restart (povolit ovládání
Finderu) a při dalším vydání aktualizaci na dálku.
Volitelně tajná proměnná `ANTISHIELD_FLEET_ACTIVATION` pro celou cestu v CI.
