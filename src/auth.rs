// Authentication management
use crate::config::Config;
use crate::config::HttpAuthProtocol;
use crate::config::ProxyType;
use anyhow::Result;
use base64::Engine;
use bytes::Bytes;
use reqwest::header::{HeaderMap, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION};
use reqwest::{Client, Response, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
        self.validate_auth_config(Some(proxy_url))?;
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
                        anyhow::bail!(
                            "Windows current credentials require NTLM/Kerberos with SSPI"
                        );
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
            .connect_timeout(std::time::Duration::from_secs(self.config.connect_timeout))
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd();

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
        request_headers: Option<&HeaderMap>,
        request_body: Option<Bytes>,
    ) -> Result<Response> {
        if self.requires_sspi_handshake() {
            #[cfg(windows)]
            {
                return self
                    .send_request_with_sspi(client, method, url, request_headers, request_body)
                    .await;
            }

            #[cfg(not(windows))]
            {
                anyhow::bail!("SSPI handshake not available outside Windows");
            }
        }

        self
            .send_plain_request(client, method, url, None, request_headers, request_body)
            .await
    }

    pub async fn connect_tunnel_via_http_proxy(
        &self,
        upstream_host_port: &str,
        target_host_port: &str,
    ) -> Result<TcpStream> {
        let auth_mode = self.auth_mode();

        match auth_mode {
            ProxyAuthMode::None | ProxyAuthMode::ManualBasic => {
                let auth_header = self.basic_proxy_authorization_header()?;
                self.send_connect_request(upstream_host_port, target_host_port, auth_header.as_deref())
                    .await
            }
            ProxyAuthMode::WindowsCurrentCredentials => {
                if self.requires_sspi_handshake() {
                    #[cfg(windows)]
                    {
                        self.send_connect_request_with_sspi(upstream_host_port, target_host_port)
                            .await
                    }

                    #[cfg(not(windows))]
                    {
                        anyhow::bail!("SSPI handshake not available outside Windows");
                    }
                } else {
                    anyhow::bail!(
                        "Windows current credentials require NTLM/Kerberos with SSPI"
                    );
                }
            }
            ProxyAuthMode::UnsupportedNtlmSspi => {
                anyhow::bail!(
                    "CONNECT with manual NTLM/Kerberos is not supported. Use Windows current credentials."
                );
            }
        }
    }

    pub fn requires_sspi_handshake(&self) -> bool {
        self.config.http_auth_enabled
            && cfg!(windows)
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
        request_headers: Option<&HeaderMap>,
        request_body: Option<Bytes>,
    ) -> Result<Response> {
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|_| anyhow::anyhow!("Unsupported HTTP method: {}", method))?;
        let mut request = client.request(method, url);

        if let Some(headers) = request_headers {
            request = request.headers(headers.clone());
        }

        if let Some(body) = request_body {
            request = request.body(body);
        }

        if let Some(value) = proxy_auth_header {
            request = request.header(PROXY_AUTHORIZATION, value);
        }

        Ok(request.send().await?)
    }

    async fn send_connect_request(
        &self,
        upstream_host_port: &str,
        target_host_port: &str,
        proxy_auth_header: Option<&str>,
    ) -> Result<TcpStream> {
        let mut stream = TcpStream::connect(upstream_host_port).await?;
        self.write_connect_request(&mut stream, target_host_port, proxy_auth_header)
            .await?;

        let (status_line, _) = read_http_response_headers(&mut stream).await?;
        if !status_line.contains(" 200 ") {
            anyhow::bail!("CONNECT refused by upstream: {}", status_line);
        }

        Ok(stream)
    }

    async fn write_connect_request(
        &self,
        stream: &mut TcpStream,
        target_host_port: &str,
        proxy_auth_header: Option<&str>,
    ) -> Result<()> {
        let mut connect_request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n",
            target_host_port,
            target_host_port
        );

        if let Some(auth_header) = proxy_auth_header {
            connect_request.push_str(&format!("Proxy-Authorization: {}\r\n", auth_header));
        }
        connect_request.push_str("\r\n");

        stream.write_all(connect_request.as_bytes()).await?;
        stream.flush().await?;
        Ok(())
    }

    #[cfg(windows)]
    async fn send_request_with_sspi(
        &self,
        client: &Client,
        method: &str,
        url: &str,
        request_headers: Option<&HeaderMap>,
        request_body: Option<Bytes>,
    ) -> Result<Response> {
        let mut sspi = WindowsSspiContext::new(self.config.http_auth_protocol.clone(), &self.config.proxy_host)?;
        let mut proxy_auth_header: Option<String> = None;

        for _ in 0..6 {
            let response = self
                .send_plain_request(
                    client,
                    method,
                    url,
                    proxy_auth_header.as_deref(),
                    request_headers,
                    request_body.clone(),
                )
                .await?;

            if response.status() != StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                return Ok(response);
            }

            let challenge = extract_proxy_auth_challenge(response.headers(), sspi.header_scheme());
            if challenge.is_none() {
                anyhow::bail!(
                    "Proxy did not return a {} challenge (Proxy-Authenticate)",
                    sspi.header_scheme()
                );
            }
            let output_token = sspi.next_token(challenge.as_deref())?;
            if output_token.is_empty() {
                anyhow::bail!("SSPI produced an empty token during handshake");
            }
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

    #[cfg(windows)]
    async fn send_connect_request_with_sspi(
        &self,
        upstream_host_port: &str,
        target_host_port: &str,
    ) -> Result<TcpStream> {
        let mut stream = TcpStream::connect(upstream_host_port).await?;
        let mut sspi =
            WindowsSspiContext::new(self.config.http_auth_protocol.clone(), &self.config.proxy_host)?;
        let mut proxy_auth_header: Option<String> = None;

        for _ in 0..6 {
            self.write_connect_request(&mut stream, target_host_port, proxy_auth_header.as_deref())
                .await?;

            let (status_line, headers) = read_http_response_headers(&mut stream).await?;
            if status_line.contains(" 200 ") {
                return Ok(stream);
            }

            if !status_line.contains(" 407 ") {
                anyhow::bail!("CONNECT refused by upstream: {}", status_line);
            }

            let challenge = extract_proxy_auth_challenge(&headers, sspi.header_scheme());
            if challenge.is_none() {
                anyhow::bail!(
                    "Proxy did not return a {} challenge (Proxy-Authenticate)",
                    sspi.header_scheme()
                );
            }

            let output_token = sspi.next_token(challenge.as_deref())?;
            if output_token.is_empty() {
                anyhow::bail!("SSPI produced an empty token during CONNECT handshake");
            }

            proxy_auth_header = Some(format!(
                "{} {}",
                sspi.header_scheme(),
                base64::engine::general_purpose::STANDARD.encode(output_token)
            ));
        }

        anyhow::bail!("SSPI CONNECT handshake failed after multiple attempts (persistent 407)")
    }

    pub fn auth_mode(&self) -> ProxyAuthMode {
        if !self.config.http_auth_enabled {
            return ProxyAuthMode::None;
        }

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

    fn validate_auth_config(&self, proxy_url: Option<&str>) -> Result<()> {
        if !self.config.http_auth_enabled {
            return Ok(());
        }

        if self.config.use_current_credentials
            && matches!(self.config.http_auth_protocol, HttpAuthProtocol::BASIC)
        {
            anyhow::bail!(
                "Current credentials with BASIC is not supported. Use NTLM/Kerberos or manual BASIC credentials."
            );
        }

        if !self.config.use_current_credentials
            && matches!(
                self.config.http_auth_protocol,
                HttpAuthProtocol::NTLM | HttpAuthProtocol::KERBEROS
            )
        {
            anyhow::bail!(
                "Manual NTLM/Kerberos credentials are not supported. Use Windows current credentials."
            );
        }

        if matches!(self.config.http_auth_protocol, HttpAuthProtocol::BASIC) {
            if self.config.proxy_username.trim().is_empty() {
                anyhow::bail!("proxy_username is required for BASIC authentication");
            }

            if self.config.proxy_password.is_empty() {
                anyhow::bail!("proxy_password is required for BASIC authentication");
            }

            if !self.config.allow_insecure_basic {
                match proxy_url {
                    Some(url) if url.to_ascii_lowercase().starts_with("https://") => {}
                    Some(_) => anyhow::bail!(
                        "BASIC auth over an unencrypted proxy is blocked. Use an https proxy URL or set allow_insecure_basic=true."
                    ),
                    None => anyhow::bail!(
                        "BASIC auth without a secure proxy URL is blocked. Set allow_insecure_basic=true to proceed."
                    ),
                }
            }
        }

        Ok(())
    }

    fn basic_proxy_authorization_header(&self) -> Result<Option<String>> {
        if !self.config.http_auth_enabled {
            return Ok(None);
        }

        if self.config.use_current_credentials
            && matches!(self.config.http_auth_protocol, HttpAuthProtocol::BASIC)
        {
            anyhow::bail!(
                "Current credentials with BASIC is not supported. Use NTLM/Kerberos or manual BASIC credentials."
            );
        }

        if matches!(
            self.config.http_auth_protocol,
            HttpAuthProtocol::NTLM | HttpAuthProtocol::KERBEROS
        ) {
            return Ok(None);
        }

        if self.config.proxy_username.trim().is_empty() {
            anyhow::bail!("proxy_username is required for BASIC authentication");
        }

        if self.config.proxy_password.is_empty() {
            anyhow::bail!("proxy_password is required for BASIC authentication");
        }

        if !self.config.allow_insecure_basic {
            anyhow::bail!(
                "BASIC auth for CONNECT is blocked unless allow_insecure_basic=true"
            );
        }

        let token = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", self.config.proxy_username, self.config.proxy_password));
        Ok(Some(format!("Basic {}", token)))
    }

}

fn extract_proxy_auth_challenge(headers: &HeaderMap, scheme: &str) -> Option<Vec<u8>> {
    for value in headers.get_all(PROXY_AUTHENTICATE).iter() {
        let Ok(value_str) = value.to_str() else {
            continue;
        };

        for part in value_str.split(',') {
            let trimmed = part.trim();

            if trimmed.eq_ignore_ascii_case(scheme) {
                return None;
            }

            if let Some((prefix, rest)) = trimmed.split_once(' ') {
                if prefix.eq_ignore_ascii_case(scheme) {
                    let token = rest.trim();
                    if token.is_empty() {
                        return None;
                    }

                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(token) {
                        return Some(decoded);
                    }
                }
            }
        }
    }

    None
}

async fn read_http_response_headers(stream: &mut TcpStream) -> Result<(String, HeaderMap)> {
    let mut response = Vec::with_capacity(1024);
    let mut temp = [0u8; 512];

    loop {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            anyhow::bail!("Connection closed by upstream proxy while waiting for response");
        }
        response.extend_from_slice(&temp[..n]);

        if response.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }

        if response.len() > 32 * 1024 {
            anyhow::bail!("Upstream proxy response headers too large");
        }
    }

    let head_end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .ok_or_else(|| anyhow::anyhow!("Invalid upstream proxy response"))?;
    let head = String::from_utf8_lossy(&response[..head_end]);
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default().to_string();
    let mut headers = HeaderMap::new();

    for line in lines {
        if line.is_empty() {
            break;
        }

        let Some((name_raw, value_raw)) = line.split_once(':') else {
            continue;
        };

        let name = name_raw.trim();
        let value = value_raw.trim();
        if let (Ok(header_name), Ok(header_value)) = (
            reqwest::header::HeaderName::from_bytes(name.as_bytes()),
            reqwest::header::HeaderValue::from_str(value),
        ) {
            headers.append(header_name, header_value);
        }
    }

    Ok((status_line, headers))
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

