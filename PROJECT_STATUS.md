# PROJECT_STATUS – H&H AntiShield

Aktualizováno: 2026-10-12 (v0.6.0)

## Stav
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
  verify, audit verify).
- `app/` – Tauri 2 + React; 33 povolených příkazů, přísná CSP, služby na
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
  Každý zásah znovu ověří umístění podle kategorie a že žádný článek cesty
  není odkaz. Zápis do auditu (`cleanup`).
- Zrychlení: žádné „čištění RAM“ ani zásahy do systému. Ukončení jen šetrné
  (macOS Apple Event „quit“ s `NSAppleEventsUsageDescription` a entitlementem
  `automation.apple-events`; jinak SIGTERM; Windows `taskkill` bez /F).
  Položky po přihlášení se odkládají do `startup-disabled` v datech aplikace
  (`launchctl bootout`/`bootstrap`), vlastní agent nejde vypnout.
- Hlídání nebezpečného chování programů se do 0.6 nedostalo; aplikace ho
  nikde netvrdí.

## Testy (2026-10-12, lokálně)
- Rust: 110 testů na Linuxu (jádro 87, CLI 2, aplikace 21) + test PKG/DMG
  jen na macOS, clippy `-D warnings`, rustfmt. Nové: čištění (nález
  a úklid, podvržená/přesunutá položka, odkazy, zbytky aplikací, právě
  používaná mezipaměť), zrychlení (měření, vratné položky po přihlášení,
  SIGTERM s ověřením konce, odmítnutí systémových programů a sebe).
- UI: 26 testů vitest (+ čištění a zrychlení: výběr, Koš zvlášť, kategorie,
  překlady, prahy disku a paměti, doporučení, doba běhu), typecheck, build.
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
- Soukromé klíče `hh-test-2026-10` a `hh-rules-2026-10` jsou jen v dočasném
  úložišti session; produkční patří do GitHub Secrets + záloha u uživatele.

## Vydání
Zvýšit verzi (`app/package.json`, `tauri.conf.json`, `Cargo.toml`), sloučit
do `main`, pak Actions → Release → Run workflow se zaškrtnutým „publish“.
Pravidla: Actions → Rules → Run workflow s „publish“ (jinak každé pondělí).

## Další krok
Sloučit PR #9 s 0.6.0 → Release (publish) → na Macu: Čištění (najít, projít
položky, vyčistit, ověřit instalátory v Koši), Zrychlení (ukončit aplikaci:
macOS se poprvé zeptá na ovládání; vypnout a zase zapnout položku po
přihlášení), plynulost plátna.
