fn main() {
    // Příkazy aplikace jsou vyjmenované, takže okno smí volat jen ty,
    // které mu výslovně povolí capabilities/default.json.
    let manifest = tauri_build::AppManifest::new().commands(&[
        "engine_info",
        "protection_status",
        "run_self_test",
        "pick_targets",
        "start_scan",
        "cancel_scan",
        "recent_events",
        "last_summary",
        "check_update",
        "install_update",
    ]);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest))
        .expect("tauri-build failed");
}
