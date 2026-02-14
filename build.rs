use std::env;
use std::path::{Path, PathBuf};

fn target_profile_dir() -> Option<PathBuf> {
    let profile = env::var("PROFILE").ok()?;

    if let Ok(target_dir) = env::var("CARGO_TARGET_DIR") {
        return Some(Path::new(&target_dir).join(profile));
    }

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").ok()?;
    Some(Path::new(&manifest_dir).join("target").join(profile))
}

fn copy_runtime_dll(dll_candidates: &[PathBuf]) {
    let dll_path = match dll_candidates.iter().find(|candidate| candidate.exists()) {
        Some(path) => path,
        None => {
            println!(
                "cargo:warning=libproxy.dll introuvable dans les chemins connus; l'exécutable peut échouer au lancement"
            );
            return;
        }
    };

    let Some(profile_dir) = target_profile_dir() else {
        println!(
            "cargo:warning=Impossible de déterminer le dossier cible pour copier libproxy.dll"
        );
        return;
    };

    if let Err(e) = std::fs::create_dir_all(&profile_dir) {
        println!(
            "cargo:warning=Impossible de créer le dossier cible {}: {}",
            profile_dir.display(),
            e
        );
        return;
    }

    let out_dll = profile_dir.join("libproxy.dll");
    match std::fs::copy(dll_path, &out_dll) {
        Ok(_) => println!("cargo:warning=libproxy.dll copié vers {}", out_dll.display()),
        Err(e) => println!(
            "cargo:warning=Échec de la copie de libproxy.dll vers {}: {}",
            out_dll.display(),
            e
        ),
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=LIBPROXY_LIB_DIR");
    println!("cargo:rerun-if-env-changed=LIBPROXY_DLL_DIR");
    println!("cargo:rerun-if-env-changed=VCPKG_ROOT");

    if cfg!(target_os = "windows") {
        let mut candidates: Vec<String> = Vec::new();
        let mut dll_candidates: Vec<PathBuf> = Vec::new();

        if let Ok(dir) = env::var("LIBPROXY_DLL_DIR") {
            let dir_path = Path::new(&dir);
            dll_candidates.push(dir_path.join("libproxy.dll"));
            dll_candidates.push(dir_path.join("proxy.dll"));
        }

        if let Ok(dir) = env::var("LIBPROXY_LIB_DIR") {
            candidates.push(dir);
        }

        if let Ok(vcpkg_root) = env::var("VCPKG_ROOT") {
            candidates.push(format!("{vcpkg_root}\\installed\\x64-windows\\lib"));
            candidates.push(format!("{vcpkg_root}\\installed\\x64-windows-static\\lib"));
            candidates.push(format!("{vcpkg_root}\\installed\\x64-windows-static-md\\lib"));
        }

        if let Ok(user_profile) = env::var("USERPROFILE") {
            let default_vcpkg = format!("{user_profile}\\vcpkg");
            candidates.push(format!("{default_vcpkg}\\installed\\x64-windows\\lib"));
            candidates.push(format!("{default_vcpkg}\\installed\\x64-windows-static\\lib"));
            candidates.push(format!("{default_vcpkg}\\installed\\x64-windows-static-md\\lib"));
        }

        candidates.sort();
        candidates.dedup();

        for dir in &candidates {
            let dir_path = Path::new(dir);
            dll_candidates.push(dir_path.join("libproxy.dll"));
            dll_candidates.push(dir_path.join("proxy.dll"));

            if let Some(parent) = dir_path.parent() {
                let bin_dir = parent.join("bin");
                dll_candidates.push(bin_dir.join("libproxy.dll"));
                dll_candidates.push(bin_dir.join("proxy.dll"));
            }

            let proxy_lib = dir_path.join("proxy.lib");
            if proxy_lib.exists() {
                println!("cargo:rustc-link-search=native={dir}");
                println!("cargo:warning=libproxy trouvé: {}", proxy_lib.display());
                copy_runtime_dll(&dll_candidates);
                return;
            }

            let libproxy_lib = dir_path.join("libproxy.lib");
            if libproxy_lib.exists() {
                if let Ok(out_dir) = env::var("OUT_DIR") {
                    let out_proxy_lib = Path::new(&out_dir).join("proxy.lib");
                    if std::fs::copy(&libproxy_lib, &out_proxy_lib).is_ok() {
                        println!("cargo:rustc-link-search=native={out_dir}");
                        println!("cargo:rustc-link-search=native={dir}");
                        println!(
                            "cargo:warning=libproxy.lib trouvé et copié vers alias proxy.lib: {}",
                            out_proxy_lib.display()
                        );
                        copy_runtime_dll(&dll_candidates);
                        return;
                    }
                }
            }
        }

        println!(
            "cargo:warning=proxy.lib introuvable. Vérifiez vcpkg (x64-windows) ou définissez LIBPROXY_LIB_DIR vers le dossier contenant proxy.lib/libproxy.lib"
        );
    }
}
