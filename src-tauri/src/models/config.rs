use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// Theme mode for the application
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThemeMode {
    Light,
    Dark,
    System,
}

impl Default for ThemeMode {
    fn default() -> Self {
        Self::System
    }
}

/// Window configuration for the application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowConfig {
    /// Window width in pixels
    pub width: u32,
    /// Window height in pixels
    pub height: u32,
    /// Window x position (optional, for remembering position)
    pub x: Option<i32>,
    /// Window y position (optional, for remembering position)
    pub y: Option<i32>,
    /// Whether the window is maximized
    pub maximized: bool,
    /// Whether the window is fullscreen
    pub fullscreen: bool,
    /// Whether the window is resizable
    pub resizable: bool,
    /// Minimum window width
    pub min_width: Option<u32>,
    /// Minimum window height
    pub min_height: Option<u32>,
}

impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            width: 1200,
            height: 800,
            x: None,
            y: None,
            maximized: false,
            fullscreen: false,
            resizable: true,
            min_width: Some(800),
            min_height: Some(600),
        }
    }
}

/// Configuration for a single vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Unique identifier for the vault
    pub id: Uuid,
    /// Display name for the vault
    pub name: String,
    /// File path to the vault directory
    pub path: PathBuf,
    /// Vault file name
    pub file_name: String,
    /// Whether this vault is currently active/selected
    pub is_active: bool,
    /// Last accessed timestamp (ISO 8601 string)
    pub last_accessed: Option<String>,
    /// Whether to auto-unlock this vault on startup
    pub auto_unlock: bool,
}

impl VaultConfig {
    /// Create a new vault configuration
    pub fn new(name: String, path: PathBuf, file_name: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            path,
            file_name,
            is_active: false,
            last_accessed: None,
            auto_unlock: false,
        }
    }

    /// Get the full path to the vault file
    pub fn full_path(&self) -> PathBuf {
        self.path.join(&self.file_name)
    }

    /// Mark this vault as accessed
    pub fn mark_accessed(&mut self) {
        self.last_accessed = Some(chrono::Utc::now().to_rfc3339());
    }
}

/// Application preferences and settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppPreferences {
    /// Theme mode (light, dark, system)
    pub theme: ThemeMode,
    /// Default view when opening the application
    pub default_view: String,
    /// Whether to show file extensions
    pub show_file_extensions: bool,
    /// Whether to show hidden files
    pub show_hidden_files: bool,
    /// Default download directory
    pub download_directory: Option<PathBuf>,
    /// Whether to confirm before deleting files
    pub confirm_delete: bool,
    /// Whether to auto-save configuration changes
    pub auto_save_config: bool,
    /// Language/locale setting
    pub language: String,
    /// Whether to check for updates on startup
    pub check_updates_on_startup: bool,
    /// Whether to minimize to system tray
    pub minimize_to_tray: bool,
}

impl Default for AppPreferences {
    fn default() -> Self {
        Self {
            theme: ThemeMode::default(),
            default_view: "files".to_string(),
            show_file_extensions: true,
            show_hidden_files: false,
            download_directory: None,
            confirm_delete: true,
            auto_save_config: true,
            language: "en".to_string(),
            check_updates_on_startup: true,
            minimize_to_tray: false,
        }
    }
}

/// Main application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Configuration version for migration support
    pub version: String,
    /// Window configuration
    pub window: WindowConfig,
    /// List of configured vaults
    pub vaults: Vec<VaultConfig>,
    /// Path to the encrypted SQLite database file
    pub database_path: PathBuf,
    /// Application preferences
    pub preferences: AppPreferences,
    /// Configuration file last modified timestamp
    pub last_modified: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        // Get the user's home directory for the default database path
        let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let database_path = PathBuf::from(home_dir)
            .join("Library/Application Support/myfilestorage/secure_storage.db");

        Self {
            version: "1.0.0".to_string(),
            window: WindowConfig::default(),
            vaults: Vec::new(),
            database_path,
            preferences: AppPreferences::default(),
            last_modified: None,
        }
    }
}

impl AppConfig {
    /// Create a new default configuration
    pub fn new() -> Self {
        let mut config = Self::default();
        config.last_modified = Some(chrono::Utc::now().to_rfc3339());
        config
    }

    /// Add a new vault to the configuration
    pub fn add_vault(&mut self, vault: VaultConfig) {
        // Deactivate all other vaults if this one is active
        if vault.is_active {
            for existing_vault in &mut self.vaults {
                existing_vault.is_active = false;
            }
        }
        self.vaults.push(vault);
        self.update_modified_time();
    }

    /// Remove a vault by ID
    pub fn remove_vault(&mut self, vault_id: &Uuid) -> bool {
        let initial_len = self.vaults.len();
        self.vaults.retain(|v| v.id != *vault_id);
        let removed = self.vaults.len() != initial_len;
        if removed {
            self.update_modified_time();
        }
        removed
    }

    /// Get the currently active vault
    pub fn active_vault(&self) -> Option<&VaultConfig> {
        self.vaults.iter().find(|v| v.is_active)
    }

    /// Set a vault as active by ID
    pub fn set_active_vault(&mut self, vault_id: &Uuid) -> bool {
        let mut found = false;
        for vault in &mut self.vaults {
            if vault.id == *vault_id {
                vault.is_active = true;
                vault.mark_accessed();
                found = true;
            } else {
                vault.is_active = false;
            }
        }
        if found {
            self.update_modified_time();
        }
        found
    }

    /// Update the last modified timestamp
    pub fn update_modified_time(&mut self) {
        self.last_modified = Some(chrono::Utc::now().to_rfc3339());
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        // Check if database path is valid
        if self.database_path.to_string_lossy().is_empty() {
            return Err("Database path cannot be empty".to_string());
        }

        // Validate vault configurations
        for vault in &self.vaults {
            if vault.name.trim().is_empty() {
                return Err("Vault name cannot be empty".to_string());
            }
            if vault.file_name.trim().is_empty() {
                return Err("Vault file name cannot be empty".to_string());
            }
        }

        // Check that only one vault is active
        let active_count = self.vaults.iter().filter(|v| v.is_active).count();
        if active_count > 1 {
            return Err("Only one vault can be active at a time".to_string());
        }

        Ok(())
    }
}
