use binscope_updates::{download, fetch_die_release, UpdateManager};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Reading official DIE release metadata...");
    let release = fetch_die_release()?;
    println!("Release: {} sha256={}", release.version, release.sha256);
    println!("Downloading official DIE database...");
    let bytes = download(&release.url, Some(&release.sha256))?;
    println!("Verified {} bytes (SHA-256 OK)", bytes.len());
    let root = std::env::temp_dir().join(format!("binscope-die-verify-{}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    let zip = root.join("db.zip");
    std::fs::write(&zip, &bytes)?;
    let manager = UpdateManager::new(root.join("data"));
    let record = manager.install_die_zip(&zip, &release.version)?;
    println!(
        "Installed: {} files, status={}, message={:?}",
        record.files, record.status, record.message
    );
    let state = manager.load_state();
    println!("State: {state:?}");
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}
