use std::env;
use std::path::PathBuf;

#[cfg(target_os = "windows")]
fn compile_windows_resources() {
    let manifest_dir = match env::var("CARGO_MANIFEST_DIR") {
        Ok(value) => PathBuf::from(value),
        Err(e) => {
            println!("cargo:warning=Impossible de lire CARGO_MANIFEST_DIR: {}", e);
            return;
        }
    };

    let icon_path = manifest_dir.join("assets").join("icon.ico");
    if !icon_path.exists() {
        println!(
            "cargo:warning=assets/icon.ico introuvable; icône EXE Windows non embarquée"
        );
        return;
    }

    let mut res = winres::WindowsResource::new();
    res.set_icon(icon_path.to_string_lossy().as_ref());

    if let Err(e) = res.compile() {
        println!("cargo:warning=Échec compilation ressource icône Windows: {}", e);
    }
}

fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");

    if cfg!(target_os = "windows") {
        compile_windows_resources();
    }
}
