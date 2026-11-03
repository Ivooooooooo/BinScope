use binscope_updates::{download, UpdateManager, PEBEAR_SIG_URL};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Downloading PE-bear SIG.txt...");
    let bytes = download(PEBEAR_SIG_URL, None)?;
    let text = String::from_utf8(bytes)?;
    let root = std::env::temp_dir().join(format!("binscope-pebear-verify-{}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    let manager = UpdateManager::new(root.join("data"));
    let record = manager.install_pebear_sig(&text, "b90f1d7d96635e7a029f424a0d1d11a104821685")?;
    println!(
        "Installed: {} signatures, status={}, message={:?}",
        record.files, record.status, record.message
    );
    println!("State: {:?}", manager.load_state());
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}
