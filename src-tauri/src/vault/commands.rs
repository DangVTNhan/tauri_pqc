use std::fs;
use std::path::PathBuf;
use tauri::State;
use crate::config::commands::ConfigState;
use crate::models::{
    AppError, AppResult, CreateVaultRequest, CreateVaultResponse,
    VaultMasterKey, VaultMetadata, VaultConfig
};
use crate::store::encryption::EncryptionService;

/// Create a new vault with encrypted directory structure
#[tauri::command]
pub async fn create_vault(
    state: State<'_, ConfigState>,
    request: CreateVaultRequest,
) -> AppResult<CreateVaultResponse> {
    // Validate input
    if request.name.trim().is_empty() {
        return Err(AppError::InternalError("Vault name cannot be empty".to_string()));
    }

    if request.password.len() < 8 {
        return Err(AppError::InternalError("Password must be at least 8 characters long".to_string()));
    }

    // Sanitize vault name for directory creation
    let sanitized_name = request.name
        .trim()
        .to_lowercase()
        .replace(char::is_whitespace, "_")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .collect::<String>();

    if sanitized_name.is_empty() {
        return Err(AppError::InternalError("Invalid vault name".to_string()));
    }

    // Create vault directory path
    let parent_path = PathBuf::from(&request.path);
    let vault_dir = parent_path.join(&sanitized_name);

    // Check if vault directory already exists
    if vault_dir.exists() {
        return Err(AppError::InternalError(format!(
            "Vault directory already exists: {}",
            vault_dir.display()
        )));
    }

    // Create vault directory
    fs::create_dir_all(&vault_dir)
        .map_err(|e| AppError::InternalError(format!(
            "Failed to create vault directory: {}",
            e
        )))?;

    // Generate master key from password
    let master_key = VaultMasterKey::new(&request.password)
        .map_err(|e| AppError::InternalError(format!(
            "Failed to generate master key: {}",
            e
        )))?;

    // Create vault metadata
    let vault_metadata = VaultMetadata::new(request.name.clone(), vault_dir.clone());

    // Create encryption service with master key
    let decrypted_master_key = master_key.decrypt_master_key(&request.password)
        .map_err(|e| AppError::InternalError(format!(
            "Failed to decrypt master key: {}",
            e
        )))?;

    // Convert Vec<u8> to [u8; 32] for MasterKey::from_bytes
    let mut key_array = [0u8; 32];
    if decrypted_master_key.len() != 32 {
        return Err(AppError::InternalError("Invalid master key length".to_string()));
    }
    key_array.copy_from_slice(&decrypted_master_key);

    let master_key_obj = crate::store::encryption::MasterKey::from_bytes(key_array);
    let encryption_service = EncryptionService::with_master_key(master_key_obj);

    // Encrypt and save master key file
    let master_key_json = serde_json::to_vec(&master_key)
        .map_err(|e| AppError::InternalError(format!(
            "Failed to serialize master key: {}",
            e
        )))?;

    let master_key_path = vault_dir.join("masterkey.silvertiger");
    fs::write(&master_key_path, &master_key_json)
        .map_err(|e| AppError::InternalError(format!(
            "Failed to write master key file: {}",
            e
        )))?;

    // Encrypt and save vault config file
    let encrypted_metadata = encryption_service.encrypt_serialize(&vault_metadata)
        .map_err(|e| AppError::InternalError(format!(
            "Failed to encrypt vault metadata: {}",
            e
        )))?;

    let metadata_json = serde_json::to_vec(&encrypted_metadata)
        .map_err(|e| AppError::InternalError(format!(
            "Failed to serialize encrypted metadata: {}",
            e
        )))?;

    let config_path = vault_dir.join("vault_config.silvertiger");
    fs::write(&config_path, &metadata_json)
        .map_err(|e| AppError::InternalError(format!(
            "Failed to write vault config file: {}",
            e
        )))?;

    // Create vault configuration for app config
    let vault_config = VaultConfig::new(
        request.name.clone(),
        parent_path,
        sanitized_name,
    );

    // Add vault to application configuration
    {
        let mut manager = state.manager.lock()
            .map_err(|e| AppError::InternalError(format!(
                "Failed to lock config manager: {}",
                e
            )))?;

        let config = manager.get_config_mut();
        config.add_vault(vault_config.clone());
        manager.save_config()
            .map_err(|e| AppError::InternalError(format!(
                "Failed to save configuration: {}",
                e
            )))?;
    }

    Ok(CreateVaultResponse {
        vault_config,
        message: format!("Vault '{}' created successfully", request.name),
    })
}

/// Verify vault password by attempting to decrypt master key
#[tauri::command]
pub async fn verify_vault_password(
    vault_path: String,
    password: String,
) -> AppResult<bool> {
    let vault_dir = PathBuf::from(&vault_path);
    let master_key_path = vault_dir.join("masterkey.silvertiger");

    if !master_key_path.exists() {
        return Err(AppError::InternalError("Master key file not found".to_string()));
    }

    // Read and deserialize master key
    let master_key_data = fs::read(&master_key_path)
        .map_err(|e| AppError::InternalError(format!(
            "Failed to read master key file: {}",
            e
        )))?;

    let master_key: VaultMasterKey = serde_json::from_slice(&master_key_data)
        .map_err(|e| AppError::InternalError(format!(
            "Failed to deserialize master key: {}",
            e
        )))?;

    Ok(master_key.verify_password(&password))
}

/// Load vault metadata (requires password)
#[tauri::command]
pub async fn load_vault_metadata(
    vault_path: String,
    password: String,
) -> AppResult<VaultMetadata> {
    let vault_dir = PathBuf::from(&vault_path);
    let master_key_path = vault_dir.join("masterkey.silvertiger");
    let config_path = vault_dir.join("vault_config.silvertiger");

    if !master_key_path.exists() {
        return Err(AppError::InternalError("Master key file not found".to_string()));
    }

    if !config_path.exists() {
        return Err(AppError::InternalError("Vault config file not found".to_string()));
    }

    // Read and deserialize master key
    let master_key_data = fs::read(&master_key_path)
        .map_err(|e| AppError::InternalError(format!(
            "Failed to read master key file: {}",
            e
        )))?;

    let master_key: VaultMasterKey = serde_json::from_slice(&master_key_data)
        .map_err(|e| AppError::InternalError(format!(
            "Failed to deserialize master key: {}",
            e
        )))?;

    // Decrypt master key with password
    let decrypted_master_key = master_key.decrypt_master_key(&password)
        .map_err(|e| AppError::InternalError(format!(
            "Failed to decrypt master key (wrong password?): {}",
            e
        )))?;

    // Create encryption service
    // Convert Vec<u8> to [u8; 32] for MasterKey::from_bytes
    let mut key_array = [0u8; 32];
    if decrypted_master_key.len() != 32 {
        return Err(AppError::InternalError("Invalid master key length".to_string()));
    }
    key_array.copy_from_slice(&decrypted_master_key);

    let master_key_obj = crate::store::encryption::MasterKey::from_bytes(key_array);
    let encryption_service = EncryptionService::with_master_key(master_key_obj);

    // Read and decrypt vault config
    let config_data = fs::read(&config_path)
        .map_err(|e| AppError::InternalError(format!(
            "Failed to read vault config file: {}",
            e
        )))?;

    let encrypted_metadata: crate::store::encryption::EncryptedData =
        serde_json::from_slice(&config_data)
            .map_err(|e| AppError::InternalError(format!(
                "Failed to deserialize encrypted metadata: {}",
                e
            )))?;

    let vault_metadata: VaultMetadata = encryption_service
        .decrypt_deserialize(&encrypted_metadata)
        .map_err(|e| AppError::InternalError(format!(
            "Failed to decrypt vault metadata: {}",
            e
        )))?;

    Ok(vault_metadata)
}

/// Check if a directory is a valid vault
#[tauri::command]
pub async fn is_valid_vault(vault_path: String) -> AppResult<bool> {
    let vault_dir = PathBuf::from(&vault_path);
    let master_key_path = vault_dir.join("masterkey.silvertiger");
    let config_path = vault_dir.join("vault_config.silvertiger");

    Ok(master_key_path.exists() && config_path.exists())
}
