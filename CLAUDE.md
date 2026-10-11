# Pracovní režim – H&H AntiShield

FAST → FOCUSED → CORRECT → VERIFIED → DONE. Šetři tokeny, ne na úkor kvality.

- Stručně. Neopakuj zadání ani známé závěry. Jakmile víš dost, jednej.
- Čti jen relevantní části souborů, hledej cíleně, dělej malé přesné změny.
  Žádné nesouvisející úpravy, kosmetické refaktoringy, duplicity ani
  nevyžádané funkce.
- Jedno nejlepší řešení, dotažené end-to-end. Chybu oprav v příčině.
- Spouštěj jen relevantní testy. Bezpečnostní změny vždy otestuj. Nikdy
  netvrď neprovedený test; neimplementovanou ochranu neoznačuj za funkční.
- Bezpečnost a správnost mají přednost před úsporou tokenů.
- Ptej se jen u nejednoznačného zadání s bezpečnostním rizikem.
- Na konci milníku aktualizuj `PROJECT_STATUS.md` (skutečný stav,
  rozhodnutí, testy, další krok).
- Odpověď: HOTOVO / OVĚŘENÍ / DALŠÍ KROK.
- Projekt je oddělený od hhsecurity a hhcloud; nic v nich neměň.
- V cloudovém kontejneru spouštěj cargo s `RUSTUP_TOOLCHAIN=stable`
  (toolchain 1.97.0 nejde stáhnout).
