// Main entry point - lance l'interface graphique
#![windows_subsystem = "windows"]

mod config;
mod proxy;
mod gui;
mod auth;
mod pac;

use eframe::egui;

const LOG_DIR_NAME: &str = "WinfoomRust";
const LOG_FILE_PREFIX: &str = "winfoom.log";
const MAX_LOG_FILES: usize = 14;

fn cleanup_old_logs(log_dir: &std::path::Path) {
    let entries = match std::fs::read_dir(log_dir) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!("Impossible de lire le dossier de logs {:?}: {}", log_dir, e);
            return;
        }
    };

    let mut log_files: Vec<(std::path::PathBuf, std::time::SystemTime)> = entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            let name = path.file_name()?.to_str()?;

            if !name.starts_with(LOG_FILE_PREFIX) {
                return None;
            }

            let modified = entry
                .metadata()
                .ok()
                .and_then(|meta| meta.modified().ok())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);

            Some((path, modified))
        })
        .collect();

    log_files.sort_by(|a, b| b.1.cmp(&a.1));

    for (old_path, _) in log_files.into_iter().skip(MAX_LOG_FILES) {
        if let Err(e) = std::fs::remove_file(&old_path) {
            tracing::warn!("Impossible de supprimer ancien log {:?}: {}", old_path, e);
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Charger la configuration
    let config = config::Config::load().unwrap_or_default();

    // Préparer le dossier de logs
    let log_dir = {
        let app_data = dirs::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let winfoom_dir = app_data.join(LOG_DIR_NAME);
        let _ = std::fs::create_dir_all(&winfoom_dir);
        winfoom_dir
    };

    cleanup_old_logs(&log_dir);
    
    // Utiliser tracing_appender avec rotation quotidienne
    let file_appender = tracing_appender::rolling::daily(&log_dir, LOG_FILE_PREFIX);
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new(config.log_level.clone()))
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    
    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_env_filter(env_filter)
        .init();

    tracing::info!("Démarrage de WinfoomRust");
    tracing::info!("Dossier de logs: {:?}", log_dir);
    tracing::info!("Rétention logs: {} fichiers max", MAX_LOG_FILES);
    
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
