use std::env;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=LIBPROXY_LIB_DIR");
    println!("cargo:rerun-if-env-changed=VCPKG_ROOT");

    if cfg!(target_os = "windows") {
        let mut candidates: Vec<String> = Vec::new();

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
            let proxy_lib = dir_path.join("proxy.lib");
            if proxy_lib.exists() {
                println!("cargo:rustc-link-search=native={dir}");
                println!("cargo:warning=libproxy trouvé: {}", proxy_lib.display());
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
