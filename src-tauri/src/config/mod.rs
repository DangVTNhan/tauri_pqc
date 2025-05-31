use std::fs;
use std::path::{Path, PathBuf};
use tauri::Manager;
use serde_json;

use crate::models::{AppConfig, AppResult, AppError};

pub mod commands;

/// Configuration manager for handling application configuration
pub struct ConfigManager {
    config_path: PathBuf,
    config: AppConfig,
}

impl ConfigManager {
    /// Create a new configuration manager
    pub fn new(app_handle: &tauri::AppHandle) -> AppResult<Self> {
        let config_path = Self::get_config_path(app_handle)?;
        let config = Self::load_or_create_config(&config_path)?;

        Ok(Self {
            config_path,
            config,
        })
    }

    /// Create a new configuration manager with a specific path (for testing)
    #[cfg(test)]
    pub fn new_with_path(config_path: PathBuf) -> AppResult<Self> {
        let config = Self::load_or_create_config(&config_path)?;

        Ok(Self {
            config_path,
            config,
        })
    }

    /// Get the configuration file path
    pub fn get_config_path(_app_handle: &tauri::AppHandle) -> AppResult<PathBuf> {
        // Use the user's home directory: ~/Library/Application Support/myfilestorage/settings.json
        let home_dir = std::env::var("HOME")
            .map_err(|e| AppError::InternalError(format!("Failed to get home directory: {}", e)))?;
        let config_dir = PathBuf::from(home_dir).join("Library/Application Support/myfilestorage");
        let config_path = config_dir.join("settings.json");

        // Ensure the config directory exists
        if !config_dir.exists() {
            fs::create_dir_all(&config_dir)
                .map_err(|e| AppError::InternalError(format!("Failed to create config directory: {}", e)))?;
        }

        Ok(config_path)
    }

    /// Load configuration from file or create default if it doesn't exist
    pub fn load_or_create_config(config_path: &Path) -> AppResult<AppConfig> {
        if config_path.exists() {
            Self::load_config(config_path)
        } else {
            let config = AppConfig::new();
            Self::save_config_to_path(&config, config_path)?;
            Ok(config)
        }
    }

    /// Load configuration from file
    pub fn load_config(config_path: &Path) -> AppResult<AppConfig> {
        let content = fs::read_to_string(config_path)
            .map_err(|e| AppError::InternalError(format!("Failed to read config file: {}", e)))?;

        let mut config: AppConfig = serde_json::from_str(&content)
            .map_err(|e| AppError::InternalError(format!("Failed to parse config file: {}", e)))?;

        // Validate the loaded configuration
        config.validate()
            .map_err(|e| AppError::InternalError(format!("Invalid configuration: {}", e)))?;

        // Update last modified time
        config.update_modified_time();

        Ok(config)
    }

    /// Save configuration to file
    pub fn save_config(&mut self) -> AppResult<()> {
        self.config.update_modified_time();
        Self::save_config_to_path(&self.config, &self.config_path)
    }

    /// Save configuration to a specific path
    pub fn save_config_to_path(config: &AppConfig, path: &Path) -> AppResult<()> {
        // Validate before saving
        config.validate()
            .map_err(|e| AppError::InternalError(format!("Invalid configuration: {}", e)))?;

        let content = serde_json::to_string_pretty(config)
            .map_err(|e| AppError::InternalError(format!("Failed to serialize config: {}", e)))?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)
                    .map_err(|e| AppError::InternalError(format!("Failed to create config directory: {}", e)))?;
            }
        }

        fs::write(path, content)
            .map_err(|e| AppError::InternalError(format!("Failed to write config file: {}", e)))?;

        Ok(())
    }

    /// Get the current configuration
    pub fn get_config(&self) -> &AppConfig {
        &self.config
    }

    /// Get a mutable reference to the configuration
    pub fn get_config_mut(&mut self) -> &mut AppConfig {
        &mut self.config
    }

    /// Update the configuration
    pub fn update_config(&mut self, new_config: AppConfig) -> AppResult<()> {
        // Validate the new configuration
        new_config.validate()
            .map_err(|e| AppError::InternalError(format!("Invalid configuration: {}", e)))?;

        self.config = new_config;
        self.save_config()
    }

    /// Get the configuration file path
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Create a backup of the current configuration
    pub fn backup_config(&self) -> AppResult<PathBuf> {
        // Create backup in the same directory with .backup extension
        let home_dir = std::env::var("HOME")
            .map_err(|e| AppError::InternalError(format!("Failed to get home directory: {}", e)))?;
        let backup_path = PathBuf::from(home_dir)
            .join("Library/Application Support/myfilestorage/settings.json.backup");
        Self::save_config_to_path(&self.config, &backup_path)?;
        Ok(backup_path)
    }

    /// Restore configuration from backup
    pub fn restore_from_backup(&mut self) -> AppResult<()> {
        let home_dir = std::env::var("HOME")
            .map_err(|e| AppError::InternalError(format!("Failed to get home directory: {}", e)))?;
        let backup_path = PathBuf::from(home_dir)
            .join("Library/Application Support/myfilestorage/settings.json.backup");
        if !backup_path.exists() {
            return Err(AppError::InternalError("No backup file found".to_string()));
        }

        let backup_config = Self::load_config(&backup_path)?;
        self.config = backup_config;
        self.save_config()
    }

    /// Reset configuration to defaults
    pub fn reset_to_defaults(&mut self) -> AppResult<()> {
        self.config = AppConfig::new();
        self.save_config()
    }

    /// Migrate configuration to a newer version
    pub fn migrate_config(&mut self, target_version: &str) -> AppResult<bool> {
        if self.config.version == target_version {
            return Ok(false); // No migration needed
        }

        // Create backup before migration
        self.backup_config()?;

        // Perform migration based on version
        match (self.config.version.as_str(), target_version) {
            ("1.0.0", "1.1.0") => {
                // Example migration: add new fields with defaults
                // This would be implemented when we have version changes
                self.config.version = target_version.to_string();
            }
            _ => {
                return Err(AppError::InternalError(format!(
                    "Unsupported migration from {} to {}",
                    self.config.version, target_version
                )));
            }
        }

        self.save_config()?;
        Ok(true)
    }

    /// Get app data directory path
    pub fn get_app_data_dir(_app_handle: &tauri::AppHandle) -> AppResult<PathBuf> {
        // Return the custom app data directory in user's home
        let home_dir = std::env::var("HOME")
            .map_err(|e| AppError::InternalError(format!("Failed to get home directory: {}", e)))?;
        Ok(PathBuf::from(home_dir).join("Library/Application Support/myfilestorage"))
    }

    /// Ensure required directories exist
    pub fn ensure_directories(&self, app_handle: &tauri::AppHandle) -> AppResult<()> {
        let app_data_dir = Self::get_app_data_dir(app_handle)?;

        // Create app data directory
        if !app_data_dir.exists() {
            fs::create_dir_all(&app_data_dir)
                .map_err(|e| AppError::InternalError(format!("Failed to create app data directory: {}", e)))?;
        }

        // Create database directory if specified
        if let Some(db_parent) = self.config.database_path.parent() {
            if !db_parent.exists() {
                fs::create_dir_all(db_parent)
                    .map_err(|e| AppError::InternalError(format!("Failed to create database directory: {}", e)))?;
            }
        }

        // Create vault directories
        for vault in &self.config.vaults {
            if !vault.path.exists() {
                fs::create_dir_all(&vault.path)
                    .map_err(|e| AppError::InternalError(format!("Failed to create vault directory: {}", e)))?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_config_serialization() {
        let config = AppConfig::new();
        let json = serde_json::to_string_pretty(&config).unwrap();
        let deserialized: AppConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.version, deserialized.version);
        assert_eq!(config.window.width, deserialized.window.width);
    }

    #[test]
    fn test_config_validation() {
        let mut config = AppConfig::new();
        assert!(config.validate().is_ok());

        // Test invalid database path
        config.database_path = PathBuf::new();
        assert!(config.validate().is_err());
    }
}
