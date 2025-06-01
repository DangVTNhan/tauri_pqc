use tauri::{AppHandle, State};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::models::{AppConfig, VaultConfig, AppResult, AppError};
use super::ConfigManager;

/// Application state containing the configuration manager
pub struct ConfigState {
    pub manager: Arc<Mutex<ConfigManager>>,
}

impl ConfigState {
    pub fn new(app_handle: &AppHandle) -> AppResult<Self> {
        let manager = ConfigManager::new(app_handle)?;
        Ok(Self {
            manager: Arc::new(Mutex::new(manager)),
        })
    }
}

/// Load the current application configuration
#[tauri::command]
pub async fn load_config(
    state: State<'_, ConfigState>,
) -> AppResult<AppConfig> {
    let manager = state.manager.lock()
        .map_err(|e| AppError::InternalError(format!("Failed to lock config manager: {}", e)))?;

    Ok(manager.get_config().clone())
}

/// Save the application configuration
#[tauri::command]
pub async fn save_config(
    state: State<'_, ConfigState>,
    config: AppConfig,
) -> AppResult<String> {
    let mut manager = state.manager.lock()
        .map_err(|e| AppError::InternalError(format!("Failed to lock config manager: {}", e)))?;

    manager.update_config(config)?;
    Ok("Configuration saved successfully".to_string())
}

/// Get the application data directory path
#[tauri::command]
pub async fn get_app_data_dir(
    app_handle: AppHandle,
) -> AppResult<String> {
    let path = ConfigManager::get_app_data_dir(&app_handle)?;
    Ok(path.to_string_lossy().to_string())
}

/// Get the configuration file path
#[tauri::command]
pub async fn get_config_path(
    app_handle: AppHandle,
) -> AppResult<String> {
    let path = ConfigManager::get_config_path(&app_handle)?;
    Ok(path.to_string_lossy().to_string())
}

/// Add a new vault to the configuration
#[tauri::command]
pub async fn add_vault(
    state: State<'_, ConfigState>,
    vault: VaultConfig,
) -> AppResult<String> {
    let mut manager = state.manager.lock()
        .map_err(|e| AppError::InternalError(format!("Failed to lock config manager: {}", e)))?;

    let config = manager.get_config_mut();
    config.add_vault(vault.clone());
    manager.save_config()?;

    Ok(format!("Vault '{}' added successfully", vault.name))
}

/// Remove a vault from the configuration
#[tauri::command]
pub async fn remove_vault(
    state: State<'_, ConfigState>,
    vault_id: String,
) -> AppResult<String> {
    let vault_uuid = Uuid::parse_str(&vault_id)
        .map_err(|e| AppError::InternalError(format!("Invalid vault ID: {}", e)))?;

    let mut manager = state.manager.lock()
        .map_err(|e| AppError::InternalError(format!("Failed to lock config manager: {}", e)))?;

    let config = manager.get_config_mut();
    let removed = config.remove_vault(&vault_uuid);

    if removed {
        manager.save_config()?;
        Ok("Vault removed successfully".to_string())
    } else {
        Err(AppError::InternalError("Vault not found".to_string()))
    }
}



/// Update window configuration
#[tauri::command]
pub async fn update_window_config(
    state: State<'_, ConfigState>,
    window_config: crate::models::WindowConfig,
) -> AppResult<String> {
    let mut manager = state.manager.lock()
        .map_err(|e| AppError::InternalError(format!("Failed to lock config manager: {}", e)))?;

    let config = manager.get_config_mut();
    config.window = window_config;
    manager.save_config()?;

    Ok("Window configuration updated successfully".to_string())
}

/// Update application preferences
#[tauri::command]
pub async fn update_preferences(
    state: State<'_, ConfigState>,
    preferences: crate::models::AppPreferences,
) -> AppResult<String> {
    let mut manager = state.manager.lock()
        .map_err(|e| AppError::InternalError(format!("Failed to lock config manager: {}", e)))?;

    let config = manager.get_config_mut();
    config.preferences = preferences;
    manager.save_config()?;

    Ok("Preferences updated successfully".to_string())
}

/// Create a backup of the current configuration
#[tauri::command]
pub async fn backup_config(
    state: State<'_, ConfigState>,
) -> AppResult<String> {
    let manager = state.manager.lock()
        .map_err(|e| AppError::InternalError(format!("Failed to lock config manager: {}", e)))?;

    let backup_path = manager.backup_config()?;
    Ok(format!("Configuration backed up to: {}", backup_path.to_string_lossy()))
}

/// Restore configuration from backup
#[tauri::command]
pub async fn restore_config_from_backup(
    state: State<'_, ConfigState>,
) -> AppResult<String> {
    let mut manager = state.manager.lock()
        .map_err(|e| AppError::InternalError(format!("Failed to lock config manager: {}", e)))?;

    manager.restore_from_backup()?;
    Ok("Configuration restored from backup successfully".to_string())
}

/// Reset configuration to defaults
#[tauri::command]
pub async fn reset_config_to_defaults(
    state: State<'_, ConfigState>,
) -> AppResult<String> {
    let mut manager = state.manager.lock()
        .map_err(|e| AppError::InternalError(format!("Failed to lock config manager: {}", e)))?;

    manager.reset_to_defaults()?;
    Ok("Configuration reset to defaults successfully".to_string())
}

/// Validate the current configuration
#[tauri::command]
pub async fn validate_config(
    state: State<'_, ConfigState>,
) -> AppResult<String> {
    let manager = state.manager.lock()
        .map_err(|e| AppError::InternalError(format!("Failed to lock config manager: {}", e)))?;

    manager.get_config().validate()
        .map_err(|e| AppError::InternalError(e))?;

    Ok("Configuration is valid".to_string())
}

/// Ensure all required directories exist
#[tauri::command]
pub async fn ensure_directories(
    state: State<'_, ConfigState>,
    app_handle: AppHandle,
) -> AppResult<String> {
    let manager = state.manager.lock()
        .map_err(|e| AppError::InternalError(format!("Failed to lock config manager: {}", e)))?;

    manager.ensure_directories(&app_handle)?;
    Ok("All required directories created successfully".to_string())
}

/// Initialize configuration system
#[tauri::command]
pub async fn init_config_system(
    app_handle: AppHandle,
) -> AppResult<AppConfig> {
    let manager = ConfigManager::new(&app_handle)?;
    manager.ensure_directories(&app_handle)?;
    Ok(manager.get_config().clone())
}
