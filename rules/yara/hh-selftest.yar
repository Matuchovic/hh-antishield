// H&H AntiShield: neškodné pravidlo pro self-test enginu YARA.
// Je v každé sadě pravidel s YARA; engine ho ověřuje při startu.
rule HH_YARA_SELFTEST {
    meta:
        description = "H&H AntiShield self-test marker (harmless)"
        author = "H&H"
        hh_test_only = true
    strings:
        $marker = "HH-ANTISHIELD-YARA-SELFTEST-0001"
    condition:
        $marker
}
