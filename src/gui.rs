// Interface graphique avec egui
use crate::config::{Config, ProxyType, HttpAuthProtocol};
use crate::proxy::ProxyServer;
use eframe::egui;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as TokioMutex;

pub struct WinfoomApp {
    config: Config,
    proxy_server: Arc<TokioMutex<Option<ProxyServer>>>,
    is_running: bool,
    status_message: String,
    error_message: Arc<Mutex<String>>,
    show_password: bool,
    runtime: tokio::runtime::Runtime,
    initialized: bool,
    test_result: Arc<Mutex<Option<String>>>,
}

impl WinfoomApp {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            proxy_server: Arc::new(TokioMutex::new(None)),
            is_running: false,
            status_message: "Proxy arrêté".to_string(),
            error_message: Arc::new(Mutex::new(String::new())),
            show_password: false,
            runtime: tokio::runtime::Runtime::new().unwrap(),
            initialized: false,
            test_result: Arc::new(Mutex::new(None)),
        }
    }

    fn start_proxy(&mut self) {
        let config = self.config.clone();
        let proxy_server = Arc::clone(&self.proxy_server);
        let error_msg = Arc::clone(&self.error_message);
        let unsupported_ntlm_sspi =
            (self.config.use_current_credentials
                || !self.config.proxy_username.is_empty()
                || !self.config.proxy_password.is_empty())
                && matches!(
                    self.config.http_auth_protocol,
                    HttpAuthProtocol::NTLM | HttpAuthProtocol::KERBEROS
                );
        
        self.runtime.spawn(async move {
            let mut server = ProxyServer::new(config.clone());
            
            match server.start().await {
                Ok(_) => {
                    tracing::info!("Serveur proxy démarré");
                    // Sauvegarder la configuration
                    if let Err(e) = config.save() {
                        tracing::warn!("Erreur sauvegarde configuration: {}", e);
                    } else {
                        tracing::info!("Configuration sauvegardée");
                    }
                    // Effacer les erreurs précédentes
                    let mut err = error_msg.lock().unwrap();
                    err.clear();
                }
                Err(e) => {
                    let error_str = format!("Erreur démarrage proxy: {}", e);
                    tracing::error!("{}", error_str);
                    // Stocker l'erreur pour l'afficher dans l'interface
                    let mut err = error_msg.lock().unwrap();
                    *err = error_str;
                    return; // Ne pas marquer comme running si ça échoue
                }
            }
            
            let mut proxy_guard = proxy_server.lock().await;
            *proxy_guard = Some(server);
        });
        
        self.is_running = true;
        if unsupported_ntlm_sspi {
            self.status_message = format!(
                "Proxy démarré sur le port {} — NTLM/SSPI non supporté actuellement",
                self.config.local_port
            );
            tracing::warn!(
                "Mode NTLM/SSPI détecté: handshake complet non implémenté"
            );
        } else {
            self.status_message = format!("Proxy démarré sur le port {}", self.config.local_port);
        }
    }

    fn stop_proxy(&mut self) {
        let proxy_server = Arc::clone(&self.proxy_server);
        
        self.runtime.spawn(async move {
            let mut proxy_guard = proxy_server.lock().await;
            if let Some(ref mut server) = *proxy_guard {
                let _ = server.stop().await;
            }
            *proxy_guard = None;
        });
        
        self.is_running = false;
        self.status_message = "Proxy arrêté".to_string();
    }

    async fn test_connection(url: &str, local_port: u16) -> Result<String, String> {
        if url.is_empty() {
            return Err("URL de test vide".to_string());
        }

        // Créer un client HTTP qui utilise le proxy local
        let proxy_url = format!("http://127.0.0.1:{}", local_port);
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::http(&proxy_url).map_err(|e| format!("Erreur proxy: {}", e))?)
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Erreur création client: {}", e))?;

        match client.get(url).send().await {
            Ok(response) => {
                let status = response.status();
                Ok(format!(
                    "Status: {}",
                    status.as_u16(),
                ))
            }
            Err(e) => {
                Err(format!("Erreur requête: {}", e))
            }
        }
    }

    fn logs_directory() -> PathBuf {
        let app_data = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."));
        app_data.join("WinfoomRust")
    }

    fn open_logs_directory() -> Result<(), String> {
        let logs_dir = Self::logs_directory();
        std::fs::create_dir_all(&logs_dir)
            .map_err(|e| format!("Impossible de créer le dossier de logs: {}", e))?;

        #[cfg(target_os = "windows")]
        {
            Command::new("explorer")
                .arg(&logs_dir)
                .spawn()
                .map_err(|e| format!("Impossible d'ouvrir le dossier de logs: {}", e))?;
        }

        #[cfg(target_os = "macos")]
        {
            Command::new("open")
                .arg(&logs_dir)
                .spawn()
                .map_err(|e| format!("Impossible d'ouvrir le dossier de logs: {}", e))?;
        }

        #[cfg(all(unix, not(target_os = "macos")))]
        {
            Command::new("xdg-open")
                .arg(&logs_dir)
                .spawn()
                .map_err(|e| format!("Impossible d'ouvrir le dossier de logs: {}", e))?;
        }

        Ok(())
    }
}

impl eframe::App for WinfoomApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Au premier affichage, vérifier l'autostart
        if !self.initialized {
            self.initialized = true;
            if self.config.autostart {
                self.start_proxy();
            }
        }
        
        // Vérifier si le test a un résultat à afficher
        if let Some(result) = self.test_result.lock().unwrap().take() {
            self.status_message = result;
        }
        
        // Vérifier s'il y a un message d'erreur à afficher
        let error_display = {
            let err = self.error_message.lock().unwrap();
            let msg = err.clone();
            if !msg.is_empty() && self.is_running {
                // Si on a une erreur et qu'on croit qu'on est running, c'est faux
                self.is_running = false;
            }
            msg
        };
        // Menu supérieur
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("Fichier", |ui| {
                    if ui.button("Sauvegarder configuration").clicked() {
                        match self.config.save() {
                            Ok(_) => {
                                self.status_message = "Configuration sauvegardée".to_string();
                                tracing::info!("Configuration sauvegardée");
                            }
                            Err(e) => {
                                self.status_message = format!("Erreur: {}", e);
                                tracing::error!("Erreur sauvegarde config: {}", e);
                            }
                        }
                        ui.close_menu();
                    }
                    
                    if ui.button("Recharger configuration").clicked() {
                        match Config::load() {
                            Ok(config) => {
                                self.config = config;
                                self.status_message = "Configuration rechargée".to_string();
                            }
                            Err(e) => {
                                self.status_message = format!("Erreur: {}", e);
                            }
                        }
                        ui.close_menu();
                    }
                    
                    ui.separator();
                    
                    if ui.button("Quitter").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button("Aide", |ui| {
                    if ui.button("Ouvrir le dossier des logs").clicked() {
                        match Self::open_logs_directory() {
                            Ok(_) => {
                                self.status_message = "Ouverture du dossier des logs...".to_string();
                            }
                            Err(e) => {
                                self.status_message = format!("Erreur: {}", e);
                                tracing::error!("{}", e);
                            }
                        }
                        ui.close_menu();
                    }

                    if ui.button("À propos").clicked() {
                        self.status_message = "WinfoomRust v0.5.0 - Proxy Facade".to_string();
                        ui.close_menu();
                    }
                });
            });
        });

        // Panneau latéral pour les contrôles
        egui::SidePanel::left("control_panel")
            .min_width(250.0)
            .show(ctx, |ui| {
                ui.heading("Contrôles");
                ui.separator();

                // Bouton Start/Stop
                ui.horizontal(|ui| {
                    if self.is_running {
                        if ui.button("⏹ Arrêter le proxy").clicked() {
                            self.stop_proxy();
                        }
                    } else {
                        if ui.button("▶ Démarrer le proxy").clicked() {
                            self.start_proxy();
                        }
                    }
                });

                ui.add_space(10.0);

                // Status et Type de proxy
                ui.group(|ui| {
                    ui.label("Status:");
                    ui.colored_label(
                        if self.is_running { 
                            egui::Color32::GREEN 
                        } else { 
                            egui::Color32::RED 
                        },
                        if self.is_running { "● Actif" } else { "● Inactif" }
                    );
                    
                    // Afficher les erreurs s'il y en a
                    if !error_display.is_empty() {
                        ui.add_space(8.0);
                        ui.colored_label(
                            egui::Color32::RED,
                            format!("[WARNING] {}", error_display)
                        );
                        if ui.button("Effacer l'erreur").clicked() {
                            let mut err = self.error_message.lock().unwrap();
                            err.clear();
                        }
                    }
                    
                    ui.add_space(5.0);
                    
                    ui.label("Type de proxy en cours:");
                    let proxy_type_str = match self.config.proxy_type {
                        ProxyType::HTTP => "HTTP",
                        ProxyType::SOCKS4 => "SOCKS4",
                        ProxyType::SOCKS5 => "SOCKS5",
                        ProxyType::PAC => "PAC",
                        ProxyType::DIRECT => "DIRECT",
                    };
                    ui.label(egui::RichText::new(proxy_type_str).color(egui::Color32::YELLOW));
                });

                ui.add_space(10.0);
                ui.separator();

                // Port local
                ui.label("Port local:");
                ui.add(egui::DragValue::new(&mut self.config.local_port)
                    .speed(1)
                    .range(1024..=65535));

                ui.add_space(5.0);

                // URL de test
                ui.label("URL de test:");
                ui.text_edit_singleline(&mut self.config.proxy_test_url);

                ui.add_space(10.0);

                // Bouton de test
                if ui.button("Tester la connexion").clicked() {
                    self.status_message = "Test en cours...".to_string();
                    let test_url = self.config.proxy_test_url.clone();
                    let local_port = self.config.local_port;
                    let test_result = Arc::clone(&self.test_result);
                    
                    self.runtime.spawn(async move {
                        match Self::test_connection(&test_url, local_port).await {
                            Ok(info) => {
                                let msg = format!("✓ Connexion réussie: {}", info);
                                tracing::info!("{}", msg);
                                let mut result = test_result.lock().unwrap();
                                *result = Some(msg);
                            }
                            Err(e) => {
                                let msg = format!("✗ Erreur: {}", e);
                                tracing::error!("{}", msg);
                                let mut result = test_result.lock().unwrap();
                                *result = Some(msg);
                            }
                        }
                    });
                }
            });

        // Panneau central pour la configuration
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Configuration du Proxy");
            ui.separator();

            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add_space(10.0);

                // Type de proxy
                ui.horizontal(|ui| {
                    ui.label("Type de proxy:");
                    ui.add_space(20.0);
                    
                    if ui.selectable_label(
                        matches!(self.config.proxy_type, ProxyType::HTTP), 
                        "HTTP"
                    ).clicked() {
                        self.config.proxy_type = ProxyType::HTTP;
                    }
                    
                    if ui.selectable_label(
                        matches!(self.config.proxy_type, ProxyType::SOCKS4), 
                        "SOCKS4"
                    ).clicked() {
                        self.config.proxy_type = ProxyType::SOCKS4;
                    }
                    
                    if ui.selectable_label(
                        matches!(self.config.proxy_type, ProxyType::SOCKS5), 
                        "SOCKS5"
                    ).clicked() {
                        self.config.proxy_type = ProxyType::SOCKS5;
                    }
                    
                    if ui.selectable_label(
                        matches!(self.config.proxy_type, ProxyType::PAC), 
                        "PAC"
                    ).clicked() {
                        self.config.proxy_type = ProxyType::PAC;
                    }
                    
                    if ui.selectable_label(
                        matches!(self.config.proxy_type, ProxyType::DIRECT), 
                        "DIRECT"
                    ).clicked() {
                        self.config.proxy_type = ProxyType::DIRECT;
                    }
                });

                ui.add_space(15.0);

                // Configuration selon le type
                match self.config.proxy_type {
                    ProxyType::HTTP | ProxyType::SOCKS4 | ProxyType::SOCKS5 => {
                        ui.group(|ui| {
                            ui.label("Configuration du proxy upstream:");
                            
                            ui.add_space(5.0);
                            ui.horizontal(|ui| {
                                ui.label("Hôte:");
                                ui.text_edit_singleline(&mut self.config.proxy_host);
                            });
                            
                            ui.horizontal(|ui| {
                                ui.label("Port:");
                                ui.add(egui::DragValue::new(&mut self.config.proxy_port)
                                    .speed(1)
                                    .range(1..=65535));
                            });
                        });

                        ui.add_space(10.0);

                        // Authentification
                        if matches!(self.config.proxy_type, ProxyType::HTTP) {
                            ui.group(|ui| {
                                ui.label("Authentification:");
                                
                                #[cfg(windows)]
                                {
                                    ui.checkbox(
                                        &mut self.config.use_current_credentials,
                                        "Utiliser les credentials Windows actuels"
                                    );
                                }

                                if !self.config.use_current_credentials {
                                    ui.add_space(5.0);
                                    
                                    ui.horizontal(|ui| {
                                        ui.label("Utilisateur:");
                                        ui.text_edit_singleline(&mut self.config.proxy_username);
                                    });
                                    
                                    ui.horizontal(|ui| {
                                        ui.label("Mot de passe:");
                                        if self.show_password {
                                            ui.text_edit_singleline(&mut self.config.proxy_password);
                                        } else {
                                            ui.add(egui::TextEdit::singleline(&mut self.config.proxy_password)
                                                .password(true));
                                        }
                                        if ui.button(if self.show_password { "🙈" } else { "👁" }).clicked() {
                                            self.show_password = !self.show_password;
                                        }
                                    });

                                    ui.add_space(5.0);
                                    ui.horizontal(|ui| {
                                        ui.label("Protocole:");
                                        ui.selectable_value(
                                            &mut self.config.http_auth_protocol,
                                            HttpAuthProtocol::NTLM,
                                            "NTLM"
                                        );
                                        ui.selectable_value(
                                            &mut self.config.http_auth_protocol,
                                            HttpAuthProtocol::BASIC,
                                            "BASIC"
                                        );
                                        ui.selectable_value(
                                            &mut self.config.http_auth_protocol,
                                            HttpAuthProtocol::KERBEROS,
                                            "KERBEROS"
                                        );
                                    });
                                }
                            });
                        }
                    }
                    ProxyType::PAC => {
                        ui.group(|ui| {
                            ui.label("Configuration PAC:");
                            
                            ui.add_space(5.0);
                            ui.horizontal(|ui| {
                                ui.label("Fichier/URL PAC:");
                                ui.text_edit_singleline(&mut self.config.proxy_pac_file_location);
                            });
                            
                            ui.add_space(5.0);
                            ui.label("💡 Peut être un chemin local ou une URL HTTP(S)");
                        });
                    }
                    ProxyType::DIRECT => {
                        ui.label("Mode DIRECT - Pas de proxy upstream");
                        ui.label("Les requêtes sont envoyées directement à leur destination.");
                    }
                }

                ui.add_space(15.0);

                // Options avancées
                ui.collapsing("Options avancées", |ui| {
                    ui.add_space(5.0);
                    
                    ui.horizontal(|ui| {
                        ui.label("Timeout socket (s):");
                        ui.add(egui::DragValue::new(&mut self.config.socket_timeout)
                            .speed(1)
                            .range(5..=300));
                    });
                    
                    ui.horizontal(|ui| {
                        ui.label("Timeout connexion (s):");
                        ui.add(egui::DragValue::new(&mut self.config.connect_timeout)
                            .speed(1)
                            .range(5..=120));
                    });
                    
                    ui.horizontal(|ui| {
                        ui.label("Timeout blacklist (s):");
                        ui.add(egui::DragValue::new(&mut self.config.blacklist_timeout)
                            .speed(1)
                            .range(10..=300));
                    });
                    
                    ui.add_space(10.0);
                    
                    ui.checkbox(&mut self.config.autostart, "Démarrage automatique du proxy");
                    ui.checkbox(&mut self.config.autodetect, "Détection automatique des paramètres");
                });

                ui.add_space(20.0);
            });
        });

        // Barre de status en bas
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Status:");
                ui.label(&self.status_message);
            });
        });
    }
}
