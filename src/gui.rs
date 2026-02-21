// Graphical interface with egui
use crate::config::{Config, ProxyType, HttpAuthProtocol};
use crate::pac::PacResolver;
use crate::proxy::ProxyServer;
use crate::tray::{TrayController, TrayEvent};
use eframe::egui;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as TokioMutex;

pub struct WinfoomrustApp {
    config: Config,
    proxy_server: Arc<TokioMutex<Option<ProxyServer>>>,
    is_running: bool,
    status_message: String,
    error_message: Arc<Mutex<String>>,
    show_password: bool,
    runtime: tokio::runtime::Runtime,
    initialized: bool,
    test_result: Arc<Mutex<Option<String>>>,
    _tray_controller: Option<TrayController>,
    tray_events: Option<Receiver<TrayEvent>>,
    tray_initialized: bool,
    allow_exit: bool,
    show_configuration_window: bool,
}

struct PacSelectionInfo {
    query_url: String,
    selected_proxy: String,
    raw_entries: Vec<String>,
}

impl WinfoomrustApp {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            proxy_server: Arc::new(TokioMutex::new(None)),
            is_running: false,
            status_message: "Proxy stopped".to_string(),
            error_message: Arc::new(Mutex::new(String::new())),
            show_password: false,
            runtime: tokio::runtime::Runtime::new().unwrap(),
            initialized: false,
            test_result: Arc::new(Mutex::new(None)),
            _tray_controller: None,
            tray_events: None,
            tray_initialized: false,
            allow_exit: false,
            show_configuration_window: false,
        }
    }

    fn start_proxy(&mut self) {
        let config = self.config.clone();
        let proxy_server = Arc::clone(&self.proxy_server);
        let error_msg = Arc::clone(&self.error_message);
        let unsupported_ntlm_sspi =
            !self.config.use_current_credentials
                && (!self.config.proxy_username.is_empty() || !self.config.proxy_password.is_empty())
                && matches!(
                    self.config.http_auth_protocol,
                    HttpAuthProtocol::NTLM | HttpAuthProtocol::KERBEROS
                );
        
        self.runtime.spawn(async move {
            let mut server = ProxyServer::new(config.clone());
            
            match server.start().await {
                Ok(_) => {
                    tracing::info!("Proxy server started");
                    // Save configuration
                    if let Err(e) = config.save() {
                        tracing::warn!("Configuration save error: {}", e);
                    } else {
                        tracing::info!("Configuration saved");
                    }
                    // Clear previous errors
                    let mut err = error_msg.lock().unwrap();
                    err.clear();
                }
                Err(e) => {
                    let error_str = format!("Proxy start error: {}", e);
                    tracing::error!("{}", error_str);
                    // Store error for display in the interface
                    let mut err = error_msg.lock().unwrap();
                    *err = error_str;
                    return; // Don't mark as running if it fails
                }
            }
            
            let mut proxy_guard = proxy_server.lock().await;
            *proxy_guard = Some(server);
        });
        
        self.is_running = true;
        if unsupported_ntlm_sspi {
            self.status_message = format!(
                "Proxy started on port {} — NTLM/SSPI not currently supported",
                self.config.local_port
            );
            tracing::warn!(
                "NTLM/SSPI mode detected: full handshake not implemented"
            );
        } else {
            self.status_message = format!("Proxy started on port {}", self.config.local_port);
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
        self.status_message = "Proxy stopped".to_string();
    }

    async fn test_connection(url: &str, local_port: u16) -> Result<String, String> {
        if url.is_empty() {
            return Err("Test URL is empty".to_string());
        }

        // Create an HTTP client that uses the local proxy
        let proxy_url = format!("http://127.0.0.1:{}", local_port);
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::http(&proxy_url).map_err(|e| format!("Proxy error: {}", e))?)
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Client creation error: {}", e))?;

        match client.get(url).send().await {
            Ok(response) => {
                let status = response.status();
                Ok(format!(
                    "Status: {}",
                    status.as_u16(),
                ))
            }
            Err(e) => {
                Err(format!("Request error: {}", e))
            }
        }
    }

    async fn pac_selected_proxy_for_url(
        url: &str,
        pac_url: &str,
        cache_ttl_seconds: u64,
        stale_ttl_seconds: u64,
    ) -> Result<PacSelectionInfo, String> {
        let resolver = PacResolver::shared(pac_url, cache_ttl_seconds, stale_ttl_seconds)
            .map_err(|e| format!("PAC initialization error: {}", e))?;

        let entries = resolver
            .resolve(url)
            .await
            .map_err(|e| format!("PAC resolution error: {}", e))?;

        let raw_entries = entries.clone();

        for entry in entries {
            if let Some(proxy_url) = Self::map_pac_entry_to_proxy_url(&entry) {
                return Ok(PacSelectionInfo {
                    query_url: url.to_string(),
                    selected_proxy: proxy_url,
                    raw_entries,
                });
            }

            let trimmed = entry.trim();
            if trimmed.eq_ignore_ascii_case("DIRECT") || trimmed.eq_ignore_ascii_case("direct://") {
                return Ok(PacSelectionInfo {
                    query_url: url.to_string(),
                    selected_proxy: "DIRECT".to_string(),
                    raw_entries,
                });
            }
        }

        Ok(PacSelectionInfo {
            query_url: url.to_string(),
            selected_proxy: "DIRECT".to_string(),
            raw_entries,
        })
    }

    fn map_pac_entry_to_proxy_url(entry: &str) -> Option<String> {
        let trimmed = entry.trim();
        if trimmed.eq_ignore_ascii_case("DIRECT") || trimmed.eq_ignore_ascii_case("direct://") {
            return None;
        }

        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("socks://")
            || lower.starts_with("socks4://")
            || lower.starts_with("socks5://")
            || lower.starts_with("socks5h://")
        {
            return Some(trimmed.to_string());
        }

        let mut parts = trimmed.split_whitespace();
        let kind = parts.next()?.to_ascii_uppercase();
        let endpoint = parts.next()?;

        if parts.next().is_some() {
            return None;
        }

        let scheme = match kind.as_str() {
            "PROXY" | "HTTP" => "http",
            "SOCKS" => "socks5h",
            "SOCKS4" => "socks4",
            "SOCKS5" => "socks5h",
            _ => return None,
        };

        Some(format!("{}://{}", scheme, endpoint))
    }

    fn logs_directory() -> PathBuf {
        let app_data = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."));
        app_data.join("WinfoomRust")
    }

    fn open_logs_directory() -> Result<(), String> {
        let logs_dir = Self::logs_directory();
        std::fs::create_dir_all(&logs_dir)
            .map_err(|e| format!("Unable to create logs folder: {}", e))?;

        #[cfg(target_os = "windows")]
        {
            Command::new("explorer")
                .arg(&logs_dir)
                .spawn()
                .map_err(|e| format!("Unable to open logs folder: {}", e))?;
        }

        #[cfg(target_os = "macos")]
        {
            Command::new("open")
                .arg(&logs_dir)
                .spawn()
                .map_err(|e| format!("Unable to open logs folder: {}", e))?;
        }

        #[cfg(all(unix, not(target_os = "macos")))]
        {
            Command::new("xdg-open")
                .arg(&logs_dir)
                .spawn()
                .map_err(|e| format!("Unable to open logs folder: {}", e))?;
        }

        Ok(())
    }

    fn restart_application() -> Result<(), String> {
        let exe_path = std::env::current_exe()
            .map_err(|e| format!("Unable to determine current executable: {}", e))?;

        Command::new(exe_path)
            .spawn()
            .map_err(|e| format!("Unable to restart the application: {}", e))?;

        Ok(())
    }
}

impl eframe::App for WinfoomrustApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut restored_from_tray = false;

        if !self.tray_initialized {
            self.tray_initialized = true;
            match TrayController::create(ctx.clone()) {
                Ok((controller, rx)) => {
                    self._tray_controller = Some(controller);
                    self.tray_events = Some(rx);
                }
                Err(e) => {
                    tracing::error!("{}", e);
                    self.status_message = "Tray initialization error".to_string();
                }
            }
        }

        if let Some(tray_events) = &self.tray_events {
            while let Ok(event) = tray_events.try_recv() {
                match event {
                    TrayEvent::ShowWindow => {
                        restored_from_tray = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    }
                    TrayEvent::ExitApp => {
                        self.allow_exit = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
            }
        }

        if !self.allow_exit && !restored_from_tray && ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            self.status_message = "Application minimized to notification area".to_string();
        }

        // On first display, check autostart
        if !self.initialized {
            self.initialized = true;
            if self.config.start_minimized {
                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            }
            if self.config.autostart {
                self.start_proxy();
            }
        }
        
        // Check if test has a result to display
        if let Some(result) = self.test_result.lock().unwrap().take() {
            self.status_message = result;
        }
        
        // Check if there's an error message to display
        let error_display = {
            let err = self.error_message.lock().unwrap();
            let msg = err.clone();
            if !msg.is_empty() && self.is_running {
                // Si on a une erreur et qu'on croit qu'on est running, c'est faux
                self.is_running = false;
            }
            msg
        };
        // Top menu
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Save configuration").clicked() {
                        match self.config.save() {
                            Ok(_) => {
                                self.status_message = "Configuration saved".to_string();
                                tracing::info!("Configuration saved");
                            }
                            Err(e) => {
                                self.status_message = format!("Error: {}", e);
                                tracing::error!("Config save error: {}", e);
                            }
                        }
                        ui.close_menu();
                    }
                    
                    if ui.button("Reload configuration").clicked() {
                        match Config::load() {
                            Ok(config) => {
                                self.config = config;
                                self.status_message = "Configuration reloaded".to_string();
                            }
                            Err(e) => {
                                self.status_message = format!("Error: {}", e);
                            }
                        }
                        ui.close_menu();
                    }
                    
                    ui.separator();
                    
                    if ui.button("Quit").clicked() {
                        self.allow_exit = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button("Help", |ui| {
                    if ui.button("Open logs folder").clicked() {
                        match Self::open_logs_directory() {
                            Ok(_) => {
                                self.status_message = "Opening logs folder...".to_string();
                            }
                            Err(e) => {
                                self.status_message = format!("Error: {}", e);
                                tracing::error!("{}", e);
                            }
                        }
                        ui.close_menu();
                    }

                    if ui.button("About").clicked() {
                        self.status_message = "WinfoomRust v0.5.0 - Proxy Facade".to_string();
                        ui.close_menu();
                    }
                });
            });
        });

        // Side panel for controls
        let screen_width = ctx.input(|i| i.screen_rect().width());
        let side_default_width = (screen_width * 0.30).clamp(220.0, 360.0);
        let side_max_width = (screen_width * 0.55).clamp(300.0, 520.0);

        egui::SidePanel::left("control_panel")
            .resizable(true)
            .default_width(side_default_width)
            .min_width(200.0)
            .max_width(side_max_width)
            .show(ctx, |ui| {
                ui.heading("Controls");
                ui.separator();

                // Start/Stop button
                ui.horizontal(|ui| {
                    if self.is_running {
                        if ui.button("⏹ Stop proxy").clicked() {
                            self.stop_proxy();
                        }
                    } else {
                        if ui.button("▶ Start proxy").clicked() {
                            self.start_proxy();
                        }
                    }
                });

                ui.add_space(10.0);

                // Status and Proxy type
                ui.group(|ui| {
                    ui.label("Status:");
                    ui.colored_label(
                        if self.is_running { 
                            egui::Color32::GREEN 
                        } else { 
                            egui::Color32::RED 
                        },
                        if self.is_running { "● Active" } else { "● Inactive" }
                    );
                    
                    // Display errors if any
                    if !error_display.is_empty() {
                        ui.add_space(8.0);
                        ui.colored_label(
                            egui::Color32::RED,
                            format!("[WARNING] {}", error_display)
                        );
                        if ui.button("Clear error").clicked() {
                            let mut err = self.error_message.lock().unwrap();
                            err.clear();
                        }
                    }
                    
                    ui.add_space(5.0);
                    
                    ui.label("Current proxy type:");
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

                // Local port
                ui.label("Local port:");
                ui.add(egui::DragValue::new(&mut self.config.local_port)
                    .speed(1)
                    .range(1024..=65535));

                ui.add_space(5.0);

                // Test URL
                ui.label("Test URL:");
                ui.text_edit_singleline(&mut self.config.proxy_test_url);

                ui.add_space(10.0);

                // Test button
                if ui.button("Test connection").clicked() {
                    self.status_message = "Testing...".to_string();
                    let test_url = self.config.proxy_test_url.clone();
                    let local_port = self.config.local_port;
                    let proxy_type = self.config.proxy_type.clone();
                    let pac_url = self.config.proxy_pac_file_location.clone();
                    let pac_cache_ttl_seconds = self.config.pac_cache_ttl_seconds;
                    let pac_stale_ttl_seconds = self.config.pac_stale_ttl_seconds;
                    let test_result = Arc::clone(&self.test_result);
                    
                    self.runtime.spawn(async move {
                        let pac_selection_info = if matches!(proxy_type, ProxyType::PAC) {
                            match Self::pac_selected_proxy_for_url(
                                &test_url,
                                &pac_url,
                                pac_cache_ttl_seconds,
                                pac_stale_ttl_seconds,
                            )
                            .await
                            {
                                Ok(info) => Some(info),
                                Err(e) => Some(PacSelectionInfo {
                                    query_url: test_url.clone(),
                                    selected_proxy: format!("unavailable ({})", e),
                                    raw_entries: Vec::new(),
                                }),
                            }
                        } else {
                            None
                        };

                        match Self::test_connection(&test_url, local_port).await {
                            Ok(info) => {
                                let msg = if let Some(pac) = pac_selection_info {
                                    let raw = if pac.raw_entries.is_empty() {
                                        "[]".to_string()
                                    } else {
                                        format!("[{}]", pac.raw_entries.join(", "))
                                    };
                                    format!(
                                        "✓ Connection successful: {} | URL sent to PAC: {} | Raw PAC: {} | Selected PAC proxy: {}",
                                        info,
                                        pac.query_url,
                                        raw,
                                        pac.selected_proxy
                                    )
                                } else {
                                    format!("✓ Connection successful: {}", info)
                                };
                                tracing::info!("{}", msg);
                                let mut result = test_result.lock().unwrap();
                                *result = Some(msg);
                            }
                            Err(e) => {
                                let msg = if let Some(pac) = pac_selection_info {
                                    let raw = if pac.raw_entries.is_empty() {
                                        "[]".to_string()
                                    } else {
                                        format!("[{}]", pac.raw_entries.join(", "))
                                    };
                                    format!(
                                        "✗ Error: {} | URL sent to PAC: {} | Raw PAC: {} | Selected PAC proxy: {}",
                                        e,
                                        pac.query_url,
                                        raw,
                                        pac.selected_proxy
                                    )
                                } else {
                                    format!("✗ Error: {}", e)
                                };
                                tracing::error!("{}", msg);
                                let mut result = test_result.lock().unwrap();
                                *result = Some(msg);
                            }
                        }
                    });
                }
            });

        // Central panel for configuration
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Proxy Configuration");
            ui.separator();

            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add_space(10.0);

                // Proxy type
                ui.horizontal(|ui| {
                    ui.label("Proxy type:");
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

                // Configuration by type
                match self.config.proxy_type {
                    ProxyType::HTTP | ProxyType::SOCKS4 | ProxyType::SOCKS5 => {
                        ui.group(|ui| {
                            ui.label("Upstream proxy configuration:");
                            
                            ui.add_space(5.0);
                            ui.horizontal(|ui| {
                                ui.label("Host:");
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

                        // Authentication
                        if matches!(self.config.proxy_type, ProxyType::HTTP) {
                            ui.group(|ui| {
                                ui.label("Authentication:");
                                
                                #[cfg(windows)]
                                {
                                    ui.checkbox(
                                        &mut self.config.use_current_credentials,
                                        "Use current Windows credentials"
                                    );
                                }

                                if !self.config.use_current_credentials {
                                    ui.add_space(5.0);
                                    
                                    ui.horizontal(|ui| {
                                        ui.label("Username:");
                                        ui.text_edit_singleline(&mut self.config.proxy_username);
                                    });
                                    
                                    ui.horizontal(|ui| {
                                        ui.label("Password:");
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
                                        ui.label("Protocol:");
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
                            ui.label("PAC Configuration:");
                            
                            ui.add_space(5.0);
                            ui.horizontal(|ui| {
                                ui.label("PAC File/URL:");
                                ui.text_edit_singleline(&mut self.config.proxy_pac_file_location);
                            });
                            
                            ui.add_space(5.0);
                            ui.label("💡 Can be a local path or an HTTP(S) URL");
                        });
                    }
                    ProxyType::DIRECT => {
                        ui.label("DIRECT mode - No upstream proxy");
                        ui.label("Requests are sent directly to their destination.");
                    }
                }

                ui.add_space(15.0);

                // Advanced options
                ui.collapsing("Advanced options", |ui| {
                    ui.add_space(5.0);
                    
                    ui.horizontal(|ui| {
                        ui.label("Socket timeout (s):");
                        ui.add(egui::DragValue::new(&mut self.config.socket_timeout)
                            .speed(1)
                            .range(5..=300));
                    });
                    
                    ui.horizontal(|ui| {
                        ui.label("Connection timeout (s):");
                        ui.add(egui::DragValue::new(&mut self.config.connect_timeout)
                            .speed(1)
                            .range(5..=120));
                    });
                    
                    ui.horizontal(|ui| {
                        ui.label("Blacklist timeout (s):");
                        ui.add(egui::DragValue::new(&mut self.config.blacklist_timeout)
                            .speed(1)
                            .range(10..=300));
                    });

                    ui.horizontal(|ui| {
                        ui.label("PAC fresh cache (s):");
                        ui.add(egui::DragValue::new(&mut self.config.pac_cache_ttl_seconds)
                            .speed(1)
                            .range(30..=600));
                    });

                    ui.horizontal(|ui| {
                        ui.label("PAC stale max (s):");
                        ui.add(egui::DragValue::new(&mut self.config.pac_stale_ttl_seconds)
                            .speed(1)
                            .range(60..=3600));
                    });

                    ui.add_space(10.0);
                    ui.checkbox(&mut self.config.autodetect, "Automatic parameter detection");
                });

                // Application settings
                ui.collapsing("Application settings", |ui| {
                    ui.add_space(5.0);

                    ui.checkbox(&mut self.config.autostart, "Auto-start proxy");
                    ui.checkbox(&mut self.config.start_minimized, "Start application minimized");

                    ui.add_space(5.0);
                    ui.separator();
                    ui.add_space(5.0);

                    let mut debug_logs_enabled = self.config.log_level.eq_ignore_ascii_case("debug");
                    if ui.checkbox(&mut debug_logs_enabled, "Enable debug logs").changed() {
                        self.config.log_level = if debug_logs_enabled {
                            "debug".to_string()
                        } else {
                            "info".to_string()
                        };
                        self.status_message = format!(
                            "Configured log level: {} (restart required)",
                            self.config.log_level
                        );
                    }

                    ui.label(format!("Configured log level: {}", self.config.log_level));

                    ui.add_space(5.0);
                    ui.separator();
                    ui.add_space(5.0);

                    if ui.button("Restart application").clicked() {
                        if let Err(e) = self.config.save() {
                            self.status_message = format!("Config save error: {}", e);
                        } else {
                            match Self::restart_application() {
                                Ok(_) => {
                                    self.allow_exit = true;
                                    self.status_message = "Restarting the application...".to_string();
                                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                                }
                                Err(e) => {
                                    self.status_message = e;
                                }
                            }
                        }
                    }
                });

                ui.add_space(20.0);
            });
        });

        // Bottom status bar
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Status:");
                ui.label(&self.status_message);
            });
        });

        if self.show_configuration_window {
            // Settings are now integrated in the central panel
            self.show_configuration_window = false;
        }
    }
}
