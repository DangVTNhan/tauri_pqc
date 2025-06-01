use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::State;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::models::{
    AppError, AppResult, VaultMasterKey, VaultMetadata,
    UnlockVaultRequest, UnlockVaultResponse, LockVaultResponse,
    VaultMount, VaultStatus, WebDavState
};
use crate::store::encryption::EncryptionService;

use super::server::WebDavServerManager;

/// Global state for WebDAV operations
#[derive(Clone)]
pub struct WebDavCommandState {
    /// WebDAV server manager
    pub server_manager: Arc<WebDavServerManager>,
    /// Currently unlocked vaults (vault_id -> encryption_service)
    pub unlocked_vaults: Arc<RwLock<HashMap<Uuid, EncryptionService>>>,
    /// WebDAV state tracking
    pub webdav_state: Arc<RwLock<WebDavState>>,
}

impl WebDavCommandState {
    pub fn new() -> Self {
        Self {
            server_manager: Arc::new(WebDavServerManager::new()),
            unlocked_vaults: Arc::new(RwLock::new(HashMap::new())),
            webdav_state: Arc::new(RwLock::new(WebDavState::new())),
        }
    }
}

/// Unlock a vault with password (decrypt master key)
#[tauri::command]
pub async fn unlock_vault(
    state: State<'_, WebDavCommandState>,
    request: UnlockVaultRequest,
) -> AppResult<UnlockVaultResponse> {
    println!("Attempting to unlock vault with ID: {}", request.vault_id);

    // Find vault configuration by ID
    let vault_config = match find_vault_config_by_id(&request.vault_id).await {
        Ok(config) => {
            println!("Found vault config: {} at path: {}/{}", config.name, config.path.display(), config.file_name);
            config
        }
        Err(e) => {
            println!("Failed to find vault config: {}", e);
            return Ok(UnlockVaultResponse {
                success: false,
                vault_mount: None,
                error: Some(format!("Vault configuration not found: {}", e)),
            });
        }
    };

    let vault_path = PathBuf::from(&vault_config.path).join(&vault_config.file_name);
    println!("Looking for vault files at: {}", vault_path.display());

    // Load and verify master key
    let master_key_path = vault_path.join("masterkey.silvertiger");
    println!("Checking for master key at: {}", master_key_path.display());

    if !master_key_path.exists() {
        println!("Master key file not found at: {}", master_key_path.display());
        return Ok(UnlockVaultResponse {
            success: false,
            vault_mount: None,
            error: Some(format!("Master key file not found at: {}", master_key_path.display())),
        });
    }

    // Read and deserialize master key
    let master_key_data = std::fs::read(&master_key_path)
        .map_err(|e| AppError::InternalError(format!("Failed to read master key: {}", e)))?;

    let master_key: VaultMasterKey = serde_json::from_slice(&master_key_data)
        .map_err(|e| AppError::InternalError(format!("Failed to deserialize master key: {}", e)))?;

    // Verify password and decrypt master key
    let decrypted_master_key = match master_key.decrypt_master_key(&request.password) {
        Ok(key) => key,
        Err(_) => {
            return Ok(UnlockVaultResponse {
                success: false,
                vault_mount: None,
                error: Some("Invalid password".to_string()),
            });
        }
    };

    // Create encryption service with decrypted master key
    let mut key_array = [0u8; 32];
    if decrypted_master_key.len() != 32 {
        return Ok(UnlockVaultResponse {
            success: false,
            vault_mount: None,
            error: Some("Invalid master key length".to_string()),
        });
    }
    key_array.copy_from_slice(&decrypted_master_key);

    let master_key = crate::store::encryption::MasterKey::from_bytes(key_array);
    let encryption_service = EncryptionService::with_master_key(master_key);

    // Load vault metadata
    let vault_metadata = load_vault_metadata_internal(&vault_path, &encryption_service).await?;

    // Store unlocked vault
    {
        let mut unlocked_vaults = state.unlocked_vaults.write().await;
        unlocked_vaults.insert(request.vault_id, encryption_service.clone());
    }

    // Start WebDAV server immediately upon unlock
    match state.server_manager.start_server(
        request.vault_id,
        vault_metadata,
        encryption_service,
        vault_path,
        None, // Use default port
    ).await {
        Ok(vault_mount) => {
            // Update WebDAV state
            {
                let mut webdav_state = state.webdav_state.write().await;
                webdav_state.add_mounted_vault(vault_mount.clone());
            }

            Ok(UnlockVaultResponse {
                success: true,
                vault_mount: Some(vault_mount),
                error: None,
            })
        }
        Err(e) => Ok(UnlockVaultResponse {
            success: false,
            vault_mount: None,
            error: Some(e),
        }),
    }
}



/// Lock a vault (remove from unlocked vaults and stop WebDAV server)
#[tauri::command]
pub async fn lock_vault(
    state: State<'_, WebDavCommandState>,
    vault_id: String,
) -> AppResult<LockVaultResponse> {
    let vault_uuid = Uuid::parse_str(&vault_id)
        .map_err(|e| AppError::InternalError(format!("Invalid vault ID: {}", e)))?;

    // Stop WebDAV server if running
    let _ = state.server_manager.stop_server(&vault_uuid).await;

    // Remove from unlocked vaults
    {
        let mut unlocked_vaults = state.unlocked_vaults.write().await;
        unlocked_vaults.remove(&vault_uuid);
    }

    // Remove from WebDAV state
    {
        let mut webdav_state = state.webdav_state.write().await;
        webdav_state.remove_mounted_vault(&vault_uuid);
    }

    Ok(LockVaultResponse {
        success: true,
        error: None,
    })
}

/// Get status of all vaults
#[tauri::command]
pub async fn get_vault_statuses(
    state: State<'_, WebDavCommandState>,
) -> AppResult<HashMap<String, VaultStatus>> {
    let webdav_state = state.webdav_state.read().await;
    let mut statuses = HashMap::new();

    for vault_mount in webdav_state.list_mounted_vaults() {
        statuses.insert(vault_mount.vault_id.to_string(), vault_mount.status.clone());
    }

    Ok(statuses)
}

/// Helper function to find vault config by ID
async fn find_vault_config_by_id(vault_id: &Uuid) -> AppResult<crate::models::VaultConfig> {
    use crate::config::ConfigManager;
    use std::path::PathBuf;

    // Get the default config path
    let config_path = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("myfilestorage")
        .join("settings.json");

    // Load the app configuration to find the vault
    let config = ConfigManager::load_config(&config_path)
        .map_err(|e| AppError::InternalError(format!("Failed to load config: {}", e)))?;

    // Find the vault by ID
    for vault in &config.vaults {
        if vault.id == *vault_id {
            return Ok(vault.clone());
        }
    }

    Err(AppError::InternalError(format!("Vault with ID {} not found in configuration", vault_id)))
}

/// Helper function to load vault metadata
async fn load_vault_metadata_internal(
    vault_path: &PathBuf,
    encryption_service: &EncryptionService,
) -> AppResult<VaultMetadata> {
    let config_path = vault_path.join("vault_config.silvertiger");

    if !config_path.exists() {
        return Err(AppError::InternalError("Vault config file not found".to_string()));
    }

    // Read encrypted metadata
    let config_data = std::fs::read(&config_path)
        .map_err(|e| AppError::InternalError(format!("Failed to read vault config: {}", e)))?;

    // Deserialize the encrypted metadata
    let encrypted_metadata: crate::store::encryption::EncryptedData =
        serde_json::from_slice(&config_data)
            .map_err(|e| AppError::InternalError(format!("Failed to deserialize encrypted metadata: {}", e)))?;

    // Decrypt the vault metadata using the encryption service
    let vault_metadata: VaultMetadata = encryption_service.decrypt_deserialize(&encrypted_metadata)
        .map_err(|e| AppError::InternalError(format!("Failed to decrypt vault metadata: {}", e)))?;

    Ok(vault_metadata)
}
