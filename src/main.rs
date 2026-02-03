// Main entry point - lance l'interface graphique
#![windows_subsystem = "windows"]

mod config;
mod proxy;
mod gui;
mod auth;
mod pac;

use eframe::egui;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Créer un fichier de logs
    let log_file_path = {
        let app_data = dirs::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let winfoom_dir = app_data.join("WinfoomRust");
        let _ = std::fs::create_dir_all(&winfoom_dir);
        winfoom_dir.join("winfoom.log")
    };
    
    // Utiliser tracing_appender pour écrire dans un fichier
    let file_appender = tracing_appender::rolling::never(
        log_file_path.parent().unwrap_or_else(|| std::path::Path::new(".")),
        log_file_path.file_name().unwrap_or_default()
    );
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    
    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .init();

    tracing::info!("Démarrage de WinfoomRust");
    tracing::info!("Fichier de logs: {:?}", log_file_path);

    // Charger la configuration
    let config = config::Config::load().unwrap_or_default();
    
    // Options de l'interface graphique
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_title("WinfoomRust - Proxy Facade"),
        ..Default::default()
    };

    // Lancer l'application
    match eframe::run_native(
        "WinfoomRust",
        options,
        Box::new(|_cc| Ok(Box::new(gui::WinfoomApp::new(config)))),
    ) {
        Ok(_) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("Erreur eframe: {:?}", e)),
    }
}
