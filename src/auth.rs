// Authentication management
use crate::config::Config;
use crate::config::HttpAuthProtocol;
use crate::config::ProxyType;
use anyhow::Result;
use base64::Engine;
use reqwest::header::{HeaderMap, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION};
use reqwest::{Client, Response, StatusCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyAuthMode {
    None,
    ManualBasic,
    WindowsCurrentCredentials,
    UnsupportedNtlmSspi,
}

pub struct AuthHandler {
    config: Config,
}

impl AuthHandler {
    pub fn new(config: Config) -> Self {
        AuthHandler { config }
    }

    pub async fn create_authenticated_client(&self, proxy_url: &str) -> Result<Client> {
        tracing::debug!("Creating client with proxy: {}", proxy_url);
        
        let mut client_builder = Client::builder();
        let auth_mode = self.auth_mode();

        tracing::debug!("Selected authentication mode: {:?}", auth_mode);

        // Configure the proxy with authentication if needed
        let proxy = match reqwest::Proxy::all(proxy_url) {
            Ok(p) => match auth_mode {
                ProxyAuthMode::ManualBasic => {
                    if self.config.proxy_password.is_empty() {
                        anyhow::bail!("ManualBasic mode enabled but proxy_password is empty");
                    }

                    p.basic_auth(
                        &self.config.proxy_username,
                        &self.config.proxy_password,
                    )
                }
                ProxyAuthMode::WindowsCurrentCredentials => {
                    if self.requires_sspi_handshake() {
                        p
                    } else {
                        #[cfg(windows)]
                        {
                            let (username, password) = self.get_windows_credentials()?;
                            p.basic_auth(&username, &password)
                        }

                        #[cfg(not(windows))]
                        {
                            anyhow::bail!(
                        "WindowsCurrentCredentials mode requested on a non-Windows system"
                            );
                        }
                    }
                }
                ProxyAuthMode::UnsupportedNtlmSspi => {
                    anyhow::bail!(
                        "NTLM/SSPI mode not currently supported: full NTLM/Kerberos handshake not implemented"
                    );
                }
                ProxyAuthMode::None => p,
            },
            Err(e) => {
                tracing::error!("Error parsing proxy URL '{}': {}", proxy_url, e);
                return Err(anyhow::anyhow!("Invalid proxy URL '{}': {}", proxy_url, e));
            }
        };

        // Add the proxy to the builder
        client_builder = client_builder.proxy(proxy);

        // Timeouts
        client_builder = client_builder
            .timeout(std::time::Duration::from_secs(self.config.socket_timeout))
            .connect_timeout(std::time::Duration::from_secs(self.config.connect_timeout));

        match client_builder.build() {
            Ok(client) => {
                tracing::debug!("Client created successfully");
                Ok(client)
            },
            Err(e) => {
                tracing::error!("Client build error: {}", e);
                Err(anyhow::anyhow!("Unable to build HTTP client: {}", e))
            }
        }
    }

    pub async fn send_authenticated_request(
        &self,
        client: &Client,
        method: &str,
        url: &str,
    ) -> Result<Response> {
        if self.requires_sspi_handshake() {
            #[cfg(windows)]
            {
                return self.send_request_with_sspi(client, method, url).await;
            }

            #[cfg(not(windows))]
            {
                anyhow::bail!("SSPI handshake not available outside Windows");
            }
        }

        self.send_plain_request(client, method, url, None).await
    }

    pub fn requires_sspi_handshake(&self) -> bool {
        cfg!(windows)
            && matches!(self.config.proxy_type, ProxyType::HTTP)
            && self.config.use_current_credentials
            && matches!(
                self.config.http_auth_protocol,
                HttpAuthProtocol::NTLM | HttpAuthProtocol::KERBEROS
            )
    }

    async fn send_plain_request(
        &self,
        client: &Client,
        method: &str,
        url: &str,
        proxy_auth_header: Option<&str>,
    ) -> Result<Response> {
        let mut request = match method {
            "GET" => client.get(url),
            "HEAD" => client.head(url),
            "POST" => client.post(url),
            _ => anyhow::bail!("Unsupported HTTP method: {}", method),
        };

        if let Some(value) = proxy_auth_header {
            request = request.header(PROXY_AUTHORIZATION, value);
        }

        Ok(request.send().await?)
    }

    #[cfg(windows)]
    async fn send_request_with_sspi(
        &self,
        client: &Client,
        method: &str,
        url: &str,
    ) -> Result<Response> {
        let mut sspi = WindowsSspiContext::new(self.config.http_auth_protocol.clone(), &self.config.proxy_host)?;
        let mut proxy_auth_header: Option<String> = None;

        for _ in 0..6 {
            let response = self
                .send_plain_request(client, method, url, proxy_auth_header.as_deref())
                .await?;

            if response.status() != StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                return Ok(response);
            }

            let challenge = extract_proxy_auth_challenge(response.headers(), sspi.header_scheme());
            let output_token = sspi.next_token(challenge.as_deref())?;
            proxy_auth_header = Some(format!(
                "{} {}",
                sspi.header_scheme(),
                base64::engine::general_purpose::STANDARD.encode(output_token)
            ));
        }

        anyhow::bail!(
            "SSPI handshake failed after multiple attempts (persistent 407)"
        )
    }

    pub fn auth_mode(&self) -> ProxyAuthMode {
        if self.config.use_current_credentials
            && matches!(
                self.config.http_auth_protocol,
                HttpAuthProtocol::NTLM | HttpAuthProtocol::KERBEROS
            )
        {
            return ProxyAuthMode::WindowsCurrentCredentials;
        }

        let auth_requested = self.config.use_current_credentials
            || !self.config.proxy_username.is_empty()
            || !self.config.proxy_password.is_empty();

        if auth_requested
            && matches!(
                self.config.http_auth_protocol,
                HttpAuthProtocol::NTLM | HttpAuthProtocol::KERBEROS
            )
        {
            return ProxyAuthMode::UnsupportedNtlmSspi;
        }

        if self.config.use_current_credentials {
            ProxyAuthMode::WindowsCurrentCredentials
        } else if !self.config.proxy_username.is_empty() {
            ProxyAuthMode::ManualBasic
        } else {
            ProxyAuthMode::None
        }
    }

    #[cfg(windows)]
    pub fn get_windows_credentials(&self) -> Result<(String, String)> {
        let username = if !self.config.proxy_username.is_empty() {
            self.config.proxy_username.clone()
        } else {
            let user = std::env::var("USERNAME").unwrap_or_default();
            let domain = std::env::var("USERDOMAIN").unwrap_or_default();

            if user.is_empty() {
                anyhow::bail!("USERNAME not found in environment");
            }

            if domain.is_empty() {
                user
            } else {
                format!("{}\\{}", domain, user)
            }
        };

        let password = if !self.config.proxy_password.is_empty() {
            self.config.proxy_password.clone()
        } else {
            std::env::var("WINFOOM_PROXY_PASSWORD").unwrap_or_default()
        };

        if password.is_empty() {
            anyhow::bail!(
                "WindowsCurrentCredentials mode: password not found. Set proxy_password or WINFOOM_PROXY_PASSWORD"
            );
        }

        Ok((username, password))
    }
}

fn extract_proxy_auth_challenge(headers: &HeaderMap, scheme: &str) -> Option<Vec<u8>> {
    let scheme_lower = scheme.to_ascii_lowercase();

    for value in headers.get_all(PROXY_AUTHENTICATE).iter() {
        let Ok(value_str) = value.to_str() else {
            continue;
        };

        for part in value_str.split(',') {
            let trimmed = part.trim();
            let lower = trimmed.to_ascii_lowercase();

            if lower == scheme_lower {
                return None;
            }

            if lower.starts_with(&(scheme_lower.clone() + " ")) {
                let token = trimmed[scheme.len()..].trim();
                if token.is_empty() {
                    return None;
                }

                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(token) {
                    return Some(decoded);
                }
            }
        }
    }

    None
}

#[cfg(windows)]
struct WindowsSspiContext {
    credential: windows_sys::Win32::Security::Credentials::SecHandle,
    context: Option<windows_sys::Win32::Security::Credentials::SecHandle>,
    target_name: Vec<u16>,
    scheme: &'static str,
}

#[cfg(windows)]
impl WindowsSspiContext {
    fn new(protocol: HttpAuthProtocol, proxy_host: &str) -> Result<Self> {
        let (package, scheme) = match protocol {
            HttpAuthProtocol::NTLM => ("NTLM", "NTLM"),
            HttpAuthProtocol::KERBEROS => ("Negotiate", "Negotiate"),
            HttpAuthProtocol::BASIC => anyhow::bail!("SSPI not required for BASIC"),
        };

        if proxy_host.trim().is_empty() {
            anyhow::bail!("proxy_host is empty for SSPI handshake");
        }

        let target_spn = format!("HTTP/{}", proxy_host);
        let mut target_name: Vec<u16> = target_spn.encode_utf16().collect();
        target_name.push(0);

        let mut package_name: Vec<u16> = package.encode_utf16().collect();
        package_name.push(0);

        let mut credential = windows_sys::Win32::Security::Credentials::SecHandle {
            dwLower: 0,
            dwUpper: 0,
        };
        let mut expiry: i64 = 0;

        let status = unsafe {
            windows_sys::Win32::Security::Authentication::Identity::AcquireCredentialsHandleW(
                std::ptr::null_mut(),
                package_name.as_mut_ptr(),
                windows_sys::Win32::Security::Authentication::Identity::SECPKG_CRED_OUTBOUND,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
                &mut credential,
                &mut expiry,
            )
        };

        if status != 0 {
            anyhow::bail!("AcquireCredentialsHandleW failed: 0x{:08X}", status as u32);
        }

        Ok(Self {
            credential,
            context: None,
            target_name,
            scheme,
        })
    }

    fn header_scheme(&self) -> &'static str {
        self.scheme
    }

    fn next_token(&mut self, challenge: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut output_buffer = windows_sys::Win32::Security::Authentication::Identity::SecBuffer {
            cbBuffer: 0,
            BufferType: windows_sys::Win32::Security::Authentication::Identity::SECBUFFER_TOKEN,
            pvBuffer: std::ptr::null_mut(),
        };
        let mut output_desc = windows_sys::Win32::Security::Authentication::Identity::SecBufferDesc {
            ulVersion: windows_sys::Win32::Security::Authentication::Identity::SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut output_buffer,
        };

        let mut input_buffer_opt = challenge.map(|token| {
            windows_sys::Win32::Security::Authentication::Identity::SecBuffer {
                cbBuffer: token.len() as u32,
                BufferType: windows_sys::Win32::Security::Authentication::Identity::SECBUFFER_TOKEN,
                pvBuffer: token.as_ptr() as *mut _,
            }
        });
        let mut input_desc_opt = input_buffer_opt.as_mut().map(|input_buffer| {
            windows_sys::Win32::Security::Authentication::Identity::SecBufferDesc {
                ulVersion: windows_sys::Win32::Security::Authentication::Identity::SECBUFFER_VERSION,
                cBuffers: 1,
                pBuffers: input_buffer,
            }
        });

        let mut new_context = windows_sys::Win32::Security::Credentials::SecHandle {
            dwLower: 0,
            dwUpper: 0,
        };
        let mut attrs: u32 = 0;
        let mut expiry: i64 = 0;

        let status = unsafe {
            windows_sys::Win32::Security::Authentication::Identity::InitializeSecurityContextW(
                &mut self.credential,
                self.context
                    .as_mut()
                    .map(|ctx| ctx as *mut _)
                    .unwrap_or(std::ptr::null_mut()),
                self.target_name.as_mut_ptr(),
                windows_sys::Win32::Security::Authentication::Identity::ISC_REQ_ALLOCATE_MEMORY
                    | windows_sys::Win32::Security::Authentication::Identity::ISC_REQ_CONFIDENTIALITY
                    | windows_sys::Win32::Security::Authentication::Identity::ISC_REQ_CONNECTION,
                0,
                windows_sys::Win32::Security::Authentication::Identity::SECURITY_NATIVE_DREP,
                input_desc_opt
                    .as_mut()
                    .map(|desc| desc as *mut _)
                    .unwrap_or(std::ptr::null_mut()),
                0,
                &mut new_context,
                &mut output_desc,
                &mut attrs,
                &mut expiry,
            )
        };

        if self.context.is_none() {
            self.context = Some(new_context);
        } else if let Some(existing) = self.context.as_mut() {
            *existing = new_context;
        }

        let continue_needed =
            status == windows_sys::Win32::Foundation::SEC_I_CONTINUE_NEEDED;
        if status != 0 && !continue_needed {
            anyhow::bail!("InitializeSecurityContextW failed: 0x{:08X}", status as u32);
        }

        let token = if output_buffer.cbBuffer > 0 && !output_buffer.pvBuffer.is_null() {
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    output_buffer.pvBuffer as *const u8,
                    output_buffer.cbBuffer as usize,
                )
            };
            let out = bytes.to_vec();
            unsafe {
                windows_sys::Win32::Security::Authentication::Identity::FreeContextBuffer(output_buffer.pvBuffer);
            }
            out
        } else {
            Vec::new()
        };

        Ok(token)
    }
}

#[cfg(windows)]
impl Drop for WindowsSspiContext {
    fn drop(&mut self) {
        if let Some(mut context) = self.context.take() {
            unsafe {
                windows_sys::Win32::Security::Authentication::Identity::DeleteSecurityContext(&mut context);
            }
        }

        unsafe {
            windows_sys::Win32::Security::Authentication::Identity::FreeCredentialsHandle(&mut self.credential);
        }
    }
}

