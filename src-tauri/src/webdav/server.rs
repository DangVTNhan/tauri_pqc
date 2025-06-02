use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{RwLock, oneshot};
use tokio::net::TcpListener;
use hyper::{server::conn::http1, service::service_fn, Request, body::Incoming};
use hyper_util::rt::TokioIo;
use dav_server::{DavHandler, fakels::FakeLs};
use uuid::Uuid;

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

        // Get port to use
        let port = if let Some(port) = custom_port {
            port
        } else {
            let mut next_port = self.next_port.write().await;
            let port = *next_port;
            *next_port += 1;
            port
        };

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

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        // Start the server
        let servers_clone = self.servers.clone();
        let vault_id_clone = vault_id;
        let vault_path_clone = vault_path.clone();

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

                                tokio::task::spawn(async move {
                                    if let Err(err) = http1::Builder::new()
                                        .serve_connection(
                                            io,
                                            service_fn({
                                                move |req: Request<Incoming>| {
                                                    let dav_handler = dav_handler.clone();
                                                    async move {
                                                        // Log the incoming request
                                                        println!("WebDAV Request: {} {}", req.method(), req.uri());
                                                        println!("WebDAV Headers: {:?}", req.headers());

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
            vault_metadata.name.clone(),
            vault_path,
        );
        vault_mount.status = VaultStatus::Unlocked;
        vault_mount.webdav_config = WebDavConfig {
            host: "127.0.0.1".to_string(),
            port,
            is_running: true,
            started_at: Some(chrono::Utc::now()),
        };
        vault_mount.mount_url = Some(format!("http://127.0.0.1:{}/", port));

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
