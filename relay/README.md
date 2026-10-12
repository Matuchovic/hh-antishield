# Schránka firemní správy

Firemní správa (správce posílá firemním Macům příkazy, Macy mu posílají stav)
potřebuje místo, kde si zprávy předají: Macy bývají za NAT a na cizích sítích.
Tím místem je tato schránka. Je to Supabase (projekt Matucha, EU – Frankfurt)
s vlastním schématem `antishield_fleet`, odděleným od ostatních dat projektu.

## Co schránka vidí a co ne

- Vidí: identifikátory firem, Maců, pozvánek a příkazů, časy, velikosti zpráv
  a otisky (SHA-256) tokenů.
- Nevidí: obsah příkazů, zpráv o stavu a výsledků. Příkaz podepisuje klíč
  správce (Ed25519) a šifruje se jen pro cílový Mac (X25519, HKDF-SHA256,
  ChaCha20-Poly1305); zprávy Maců podepisuje klíč Macu a šifrují se jen pro
  správce. Klíče se při připojení svazují jednorázovým kódem pozvánky (HMAC),
  který schránka nezná, takže je nemůže vyměnit za své.
- Napadená schránka tedy nemůže Macy ovládat ani číst jejich data. Může
  zprávy zdržet nebo zahodit (Mac i správce pak vidí, že spojení vázne).

Mac navíc provede jen příkazy z pevného seznamu (kontrola, izolace hrozeb,
úklid podle kategorií) a jen v mezích, se kterými jeho uživatel souhlasil.
Soubory uživatele a Koš na dálku nikdy.

## Nasazení

`migrations/0001_antishield_fleet.sql` jde spustit znovu (`if not exists`,
`create or replace`). Tabulky nejsou přístupné přes API; volat jde jen funkce
`public.antishield_fleet_*`, a to jen rolí `anon` (veřejný klíč aplikace).
Funkce, které mažou řádky (úklid starých dat, odebrání Macu, odpojení),
potřebují při nasazení přes Supabase MCP potvrzení uživatele.

## Ověření před nasazením změn

Na zkušebním PostgreSQL (nikdy ne v Supabase):

```sh
psql -f relay/tests/supabase_roles.sql                    # role jako v Supabase
psql -1 -f relay/migrations/0001_antishield_fleet.sql     # 2×, musí projít i opakovaně
psql -f relay/tests/relay_test.sql                        # → ALL RELAY TESTS PASSED
```

Klient aplikace proti stejnému SQL: spusťte PostgREST (`PGRST_DB_SCHEMAS=public`,
`PGRST_DB_ANON_ROLE=anon`) a před něj `python3 relay/tests/gateway.py 3011`
(cesta `/rest/v1` jako v Supabase), vytvořte aktivační kód nástrojem níže
a spusťte:

```sh
ANTISHIELD_FLEET_RELAY_URL=http://127.0.0.1:3011 ANTISHIELD_FLEET_ACTIVATION=HHA1-… \
  cargo test -p antishield-app live_relay -- --ignored
```

CI pouští `live_relay_contract` proti skutečné schránce při každém běhu
(nic nezakládá), celou cestu jen s tajnou proměnnou níže.

## Aktivační kód pro správce

Založit firmu jde jen s jednorázovým aktivačním kódem:

```sh
cargo run -p antishield-cli -- fleet activation --note "H&H Security – CTO"
```

Nástroj vypíše kód (`HHA1-…`) a příkaz SQL, který uloží jen jeho otisk.
Příkaz SQL spusťte v projektu (SQL editor nebo MCP), kód předejte správci.
Ten ho zadá v aplikaci: Nastavení → Firemní správa → Spravovat firemní Macy.

Pro živý test v CI vytvořte kód s víc použitími a uložte ho do tajné
proměnné repozitáře `ANTISHIELD_FLEET_ACTIVATION`:

```sh
cargo run -p antishield-cli -- fleet activation --note "CI" --uses 100000 --days 730
```

## Limity a úklid

- Nejvýš 50 firem, 200 Maců na firmu, 50 platných pozvánek, 50 nevyřízených
  příkazů na Mac; pozvánka i příkaz platí nejvýš 8 dní.
- Velikosti: balíček pozvánky 8 KB, příkaz a výsledek 16 KB, zpráva 64 KB.
- Příkazy starší 30 dní a dávno prošlé pozvánky se mažou při práci správce
  nebo Macu.
