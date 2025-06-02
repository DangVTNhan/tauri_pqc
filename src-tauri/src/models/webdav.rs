use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// WebDAV server configuration for a vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebDavConfig {
    /// Server host (always localhost for security)
    pub host: String,
    /// Server port
    pub port: u16,
    /// Whether the server is currently running
    pub is_running: bool,
    /// Server start time
    pub started_at: Option<DateTime<Utc>>,
}

impl Default for WebDavConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(), // Default placeholder, will be replaced with vault name
            port: 8080,
            is_running: false,
            started_at: None,
        }
    }
}

/// Status of a vault in the WebDAV system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VaultStatus {
    /// Vault is locked (encrypted)
    Locked,
    /// Vault is unlocked and accessible via WebDAV
    Unlocked,
}

impl Default for VaultStatus {
    fn default() -> Self {
        Self::Locked
    }
}

/// WebDAV mount information for a vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMount {
    /// Vault ID
    pub vault_id: Uuid,
    /// Vault name
    pub vault_name: String,
    /// Vault directory path
    pub vault_path: PathBuf,
    /// Current status
    pub status: VaultStatus,
    /// WebDAV server configuration
    pub webdav_config: WebDavConfig,
    /// Mount URL for accessing via WebDAV
    pub mount_url: Option<String>,
    /// Last accessed timestamp
    pub last_accessed: Option<DateTime<Utc>>,
}

impl VaultMount {
    /// Create a new vault mount configuration
    pub fn new(vault_id: Uuid, vault_name: String, vault_path: PathBuf) -> Self {
        Self {
            vault_id,
            vault_name,
            vault_path,
            status: VaultStatus::Locked,
            webdav_config: WebDavConfig::default(),
            mount_url: None,
            last_accessed: None,
        }
    }

    /// Mark vault as accessed
    pub fn mark_accessed(&mut self) {
        self.last_accessed = Some(Utc::now());
    }

    /// Get the WebDAV mount URL
    pub fn get_mount_url(&self) -> Option<String> {
        if self.status == VaultStatus::Unlocked && self.webdav_config.is_running {
            Some(format!(
                "http://{}:{}/",
                self.webdav_config.host,
                self.webdav_config.port
            ))
        } else {
            None
        }
    }

    /// Check if vault is unlocked
    pub fn is_unlocked(&self) -> bool {
        self.status == VaultStatus::Unlocked
    }

    /// Check if WebDAV server is running
    pub fn is_webdav_running(&self) -> bool {
        self.status == VaultStatus::Unlocked && self.webdav_config.is_running
    }
}

/// Request to unlock a vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockVaultRequest {
    /// Vault ID to unlock
    pub vault_id: Uuid,
    /// User password for the vault
    pub password: String,
}



/// Response for vault unlock operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockVaultResponse {
    /// Whether unlock was successful
    pub success: bool,
    /// Vault mount information
    pub vault_mount: Option<VaultMount>,
    /// Error message if unlock failed
    pub error: Option<String>,
}



/// Response for vault lock operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockVaultResponse {
    /// Whether lock was successful
    pub success: bool,
    /// Error message if lock failed
    pub error: Option<String>,
}

/// Global WebDAV server state
#[derive(Debug, Default)]
pub struct WebDavState {
    /// Currently mounted vaults
    pub mounted_vaults: HashMap<Uuid, VaultMount>,
    /// Next available port for WebDAV servers
    pub next_port: u16,
}

impl WebDavState {
    /// Create new WebDAV state
    pub fn new() -> Self {
        Self {
            mounted_vaults: HashMap::new(),
            next_port: 8080,
        }
    }

    /// Get next available port
    pub fn get_next_port(&mut self) -> u16 {
        let port = self.next_port;
        self.next_port += 1;
        port
    }

    /// Add mounted vault
    pub fn add_mounted_vault(&mut self, vault_mount: VaultMount) {
        self.mounted_vaults.insert(vault_mount.vault_id, vault_mount);
    }

    /// Remove mounted vault
    pub fn remove_mounted_vault(&mut self, vault_id: &Uuid) -> Option<VaultMount> {
        self.mounted_vaults.remove(vault_id)
    }

    /// Get mounted vault
    pub fn get_mounted_vault(&self, vault_id: &Uuid) -> Option<&VaultMount> {
        self.mounted_vaults.get(vault_id)
    }

    /// Get mutable mounted vault
    pub fn get_mounted_vault_mut(&mut self, vault_id: &Uuid) -> Option<&mut VaultMount> {
        self.mounted_vaults.get_mut(vault_id)
    }

    /// List all mounted vaults
    pub fn list_mounted_vaults(&self) -> Vec<&VaultMount> {
        self.mounted_vaults.values().collect()
    }
}
