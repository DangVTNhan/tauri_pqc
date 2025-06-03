use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{RwLock, oneshot};
use tokio::net::TcpListener;
use hyper::{server::conn::http1, service::service_fn, Request, body::Incoming, Response, StatusCode, header::HeaderValue};
use hyper_util::rt::TokioIo;
use dav_server::{DavHandler, fakels::FakeLs};
use uuid::Uuid;
use base64::Engine;

use crate::models::vault::VaultMetadata;
use crate::models::webdav::{VaultMount, VaultStatus, WebDavConfig};
use crate::store::encryption::EncryptionService;
use super::filesystem::VaultFileSystem;

/// WebDAV server manager for handling multiple vault mounts
pub struct WebDavServerManager {
    /// Currently running servers
    servers: Arc<RwLock<HashMap<Uuid, WebDavServerInstance>>>,
    /// Next available port
    next_port: Arc<RwLock<u16>>,
}

impl WebDavServerManager {
    /// Create a new WebDAV server manager
    pub fn new() -> Self {
        Self {
            servers: Arc::new(RwLock::new(HashMap::new())),
            next_port: Arc::new(RwLock::new(8080)),
        }
    }

    /// Generate authentication credentials (using default for easier testing)
    fn generate_credentials() -> (String, String) {
        // Use default credentials for easier testing and development
        // In production, these should be configurable or randomly generated
        let username = "vault_user".to_string();
        let password = "vault_pass".to_string();

        println!("WebDAV Server using credentials - Username: {}, Password: {}", username, password);

        (username, password)
    }

    /// Check basic authentication
    fn check_auth(req: &Request<Incoming>, expected_username: &str, expected_password: &str) -> bool {
        if let Some(auth_header) = req.headers().get("authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Basic ") {
                    let encoded = &auth_str[6..];
                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                        if let Ok(credentials) = String::from_utf8(decoded) {
                            let parts: Vec<&str> = credentials.splitn(2, ':').collect();
                            if parts.len() == 2 {
                                return parts[0] == expected_username && parts[1] == expected_password;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Start a WebDAV server for a vault
    pub async fn start_server(
        &self,
        vault_id: Uuid,
        vault_metadata: VaultMetadata,
        encryption_service: EncryptionService,
        vault_path: PathBuf,
        custom_port: Option<u16>,
    ) -> Result<VaultMount, String> {
        // Check if server is already running
        {
            let servers = self.servers.read().await;
            if servers.contains_key(&vault_id) {
                return Err("Server already running for this vault".to_string());
            }
        }

        // Use fixed port 8080 for all vaults (path-based routing)
        let port = if let Some(port) = custom_port {
            port
        } else {
            8080 // Fixed port for all vaults
        };

        // Generate authentication credentials
        let (username, password) = Self::generate_credentials();

        // Create filesystem adapter
        let filesystem = VaultFileSystem::new(vault_metadata.clone(), encryption_service, vault_path.clone()).await
            .map_err(|e| format!("Failed to create filesystem: {}", e))?;

        // Create DAV handler using the encrypted filesystem
        let encrypted_fs = filesystem.into_encrypted_fs();
        let dav_handler = DavHandler::builder()
            .filesystem(Box::new(encrypted_fs))
            .locksystem(FakeLs::new())
            .build_handler();

        // Create server address
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        println!("Starting WebDAV server on {} for vault: {}", addr, vault_metadata.name);
        println!("WebDAV URL will be: http://127.0.0.1:{}/{}/", port, vault_metadata.name);

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        // Start the server
        let servers_clone = self.servers.clone();
        let vault_id_clone = vault_id;
        let vault_path_clone = vault_path.clone();
        let auth_username = username.clone();
        let auth_password = password.clone();
        let vault_name_for_mount = vault_metadata.name.clone();

        let server_handle = tokio::spawn(async move {
            let listener = match TcpListener::bind(addr).await {
                Ok(listener) => listener,
                Err(e) => {
                    eprintln!("Failed to bind to address {}: {}", addr, e);
                    return;
                }
            };

            println!("WebDAV server listening on {}", addr);
            println!("WebDAV server serving files from: {:?}", vault_path_clone.join("files"));

            let mut shutdown_rx = shutdown_rx;

            loop {
                tokio::select! {
                    // Handle incoming connections
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let dav_handler = dav_handler.clone();
                                let io = TokioIo::new(stream);

                                let auth_username_clone = auth_username.clone();
                                let auth_password_clone = auth_password.clone();
                                let vault_name_clone = vault_metadata.name.clone();
                                tokio::task::spawn(async move {
                                    if let Err(err) = http1::Builder::new()
                                        .serve_connection(
                                            io,
                                            service_fn({
                                                move |mut req: Request<Incoming>| {
                                                    let dav_handler = dav_handler.clone();
                                                    let auth_username = auth_username_clone.clone();
                                                    let auth_password = auth_password_clone.clone();
                                                    let vault_name = vault_name_clone.clone();
                                                    async move {
                                                        // Log the incoming request
                                                        println!("WebDAV Request: {} {}", req.method(), req.uri());
                                                        println!("WebDAV Headers: {:?}", req.headers());

                                                        // Check authentication
                                                        if !WebDavServerManager::check_auth(&req, &auth_username, &auth_password) {
                                                            println!("WebDAV Authentication failed");
                                                            let mut response = Response::new(hyper::body::Bytes::from("Authentication required").into());
                                                            *response.status_mut() = StatusCode::UNAUTHORIZED;
                                                            response.headers_mut().insert(
                                                                "WWW-Authenticate",
                                                                HeaderValue::from_static("Basic realm=\"WebDAV\"")
                                                            );
                                                            return Ok::<_, Infallible>(response);
                                                        }

                                                        // Handle path-based routing for vault
                                                        let original_path = req.uri().path().to_string();
                                                        let vault_prefix = format!("/{}/", vault_name);

                                                        // Strip vault prefix from path
                                                        let new_path = if original_path.starts_with(&vault_prefix) {
                                                            original_path[vault_prefix.len()-1..].to_string() // Keep the leading slash
                                                        } else if original_path == format!("/{}", vault_name) {
                                                            "/".to_string() // Root directory access
                                                        } else {
                                                            // Path doesn't match vault, return 404
                                                            println!("WebDAV path mismatch: {} doesn't match vault {}", original_path, vault_name);
                                                            let mut response = Response::new(hyper::body::Bytes::from("Not Found").into());
                                                            *response.status_mut() = StatusCode::NOT_FOUND;
                                                            return Ok::<_, Infallible>(response);
                                                        };

                                                        // Create new URI with stripped path
                                                        let mut uri_parts = req.uri().clone().into_parts();
                                                        uri_parts.path_and_query = Some(new_path.parse().unwrap_or_else(|_| "/".parse().unwrap()));
                                                        let new_uri = hyper::Uri::from_parts(uri_parts).unwrap_or_else(|_| "/".parse().unwrap());

                                                        // Update request URI
                                                        *req.uri_mut() = new_uri;

                                                        println!("WebDAV path rewritten: {} -> {}", original_path, req.uri().path());

                                                        let response = dav_handler.handle(req).await;

                                                        // Log the response status
                                                        println!("WebDAV Response: {}", response.status());

                                                        Ok::<_, Infallible>(response)
                                                    }
                                                }
                                            }),
                                        )
                                        .await
                                    {
                                        eprintln!("Failed serving connection: {:?}", err);
                                    }
                                });
                            }
                            Err(e) => {
                                eprintln!("Failed to accept connection: {}", e);
                            }
                        }
                    }
                    // Handle shutdown signal
                    _ = &mut shutdown_rx => {
                        println!("Shutting down WebDAV server for vault {}", vault_id_clone);
                        break;
                    }
                }
            }

            // Remove server from active servers list
            let mut servers = servers_clone.write().await;
            servers.remove(&vault_id_clone);
        });

        // Create server instance
        let server_instance = WebDavServerInstance {
            vault_id,
            port,
            shutdown_tx: Some(shutdown_tx),
            server_handle,
        };

        // Create vault mount
        let mut vault_mount = VaultMount::new(
            vault_id,
            vault_name_for_mount.clone(),
            vault_path,
        );
        vault_mount.status = VaultStatus::Unlocked;
        vault_mount.webdav_config = WebDavConfig {
            host: "127.0.0.1".to_string(), // Use 127.0.0.1 to match server binding
            port, // Use the actual port (custom or default 8080)
            is_running: true,
            started_at: Some(chrono::Utc::now()),
            username: Some(username),
            password: Some(password),
        };
        vault_mount.mount_url = Some(format!("http://127.0.0.1:{}/{}/", port, vault_name_for_mount));

        // Store server instance
        {
            let mut servers = self.servers.write().await;
            servers.insert(vault_id, server_instance);
        }

        Ok(vault_mount)
    }

    /// Stop a WebDAV server for a vault
    pub async fn stop_server(&self, vault_id: &Uuid) -> Result<(), String> {
        let mut servers = self.servers.write().await;

        if let Some(mut server_instance) = servers.remove(vault_id) {
            // Send shutdown signal
            if let Some(shutdown_tx) = server_instance.shutdown_tx.take() {
                let _ = shutdown_tx.send(());
            }

            // Abort the server task
            server_instance.server_handle.abort();

            println!("WebDAV server for vault {} stopped", vault_id);
            Ok(())
        } else {
            Err("No server running for this vault".to_string())
        }
    }

    /// Stop all running servers
    pub async fn stop_all_servers(&self) {
        let vault_ids: Vec<Uuid> = {
            let servers = self.servers.read().await;
            servers.keys().cloned().collect()
        };

        for vault_id in vault_ids {
            if let Err(e) = self.stop_server(&vault_id).await {
                eprintln!("Failed to stop server for vault {}: {}", vault_id, e);
            }
        }
    }

    /// Check if a server is running for a vault
    pub async fn is_server_running(&self, vault_id: &Uuid) -> bool {
        let servers = self.servers.read().await;
        servers.contains_key(vault_id)
    }

    /// Get server port for a vault
    pub async fn get_server_port(&self, vault_id: &Uuid) -> Option<u16> {
        let servers = self.servers.read().await;
        servers.get(vault_id).map(|instance| instance.port)
    }

    /// List all running servers
    pub async fn list_running_servers(&self) -> Vec<(Uuid, u16)> {
        let servers = self.servers.read().await;
        servers.iter().map(|(id, instance)| (*id, instance.port)).collect()
    }
}

impl Default for WebDavServerManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Instance of a running WebDAV server
struct WebDavServerInstance {
    vault_id: Uuid,
    port: u16,
    shutdown_tx: Option<oneshot::Sender<()>>,
    server_handle: tokio::task::JoinHandle<()>,
}

impl Drop for WebDavServerInstance {
    fn drop(&mut self) {
        // Send shutdown signal if not already sent
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }

        // Abort the server task
        self.server_handle.abort();
    }
}
