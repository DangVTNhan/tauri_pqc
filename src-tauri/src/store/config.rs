use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use super::encryption::EncryptionConfig;
use super::error::{StorageError, StorageResult};

/// Storage backend type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StorageBackend {
    /// In-memory storage (for testing)
    Memory,
    /// SQLite database storage
    SQLite,
}

impl Default for StorageBackend {
    fn default() -> Self {
        Self::SQLite
    }
}

/// SQLite-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SQLiteConfig {
    /// Database file path
    pub database_path: PathBuf,
    /// Connection pool size
    pub max_connections: u32,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Enable WAL mode for better concurrency
    pub enable_wal: bool,
    /// Enable foreign key constraints
    pub enable_foreign_keys: bool,
    /// SQLite journal mode
    pub journal_mode: String,
    /// SQLite synchronous mode
    pub synchronous: String,
    /// Cache size in KB
    pub cache_size: i32,
    /// Page size in bytes
    pub page_size: u32,
    /// Auto-vacuum mode
    pub auto_vacuum: String,
}

impl Default for SQLiteConfig {
    fn default() -> Self {
        Self {
            database_path: PathBuf::from("secure_storage.db"),
            max_connections: 10,
            connection_timeout: 30,
            enable_wal: true,
            enable_foreign_keys: true,
            journal_mode: "WAL".to_string(),
            synchronous: "NORMAL".to_string(),
            cache_size: 10240, // 10 MB
            page_size: 4096,   // 4 KB
            auto_vacuum: "INCREMENTAL".to_string(),
        }
    }
}

/// In-memory storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    /// Maximum number of items to store
    pub max_items: Option<usize>,
    /// Enable data persistence to disk
    pub persist_to_disk: bool,
    /// Persistence file path
    pub persistence_path: Option<PathBuf>,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            max_items: None,
            persist_to_disk: false,
            persistence_path: None,
        }
    }
}

/// Main storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage backend type
    pub backend: StorageBackend,
    /// Encryption configuration
    pub encryption: EncryptionConfig,
    /// SQLite-specific configuration
    pub sqlite: SQLiteConfig,
    /// Memory-specific configuration
    pub memory: MemoryConfig,
    /// Enable data compression
    pub enable_compression: bool,
    /// Compression level (1-9)
    pub compression_level: u32,
    /// Enable automatic backups
    pub enable_auto_backup: bool,
    /// Backup interval in hours
    pub backup_interval_hours: u32,
    /// Maximum number of backups to keep
    pub max_backups: u32,
    /// Backup directory
    pub backup_directory: PathBuf,
    /// Enable data integrity checks
    pub enable_integrity_checks: bool,
    /// Integrity check interval in hours
    pub integrity_check_interval_hours: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: StorageBackend::default(),
            encryption: EncryptionConfig::default(),
            sqlite: SQLiteConfig::default(),
            memory: MemoryConfig::default(),
            enable_compression: false,
            compression_level: 6,
            enable_auto_backup: true,
            backup_interval_hours: 24,
            max_backups: 7,
            backup_directory: PathBuf::from("backups"),
            enable_integrity_checks: true,
            integrity_check_interval_hours: 168, // Weekly
        }
    }
}

impl StorageConfig {
    /// Create a new storage configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set storage backend
    pub fn with_backend(mut self, backend: StorageBackend) -> Self {
        self.backend = backend;
        self
    }

    /// Set SQLite database path
    pub fn with_sqlite_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.sqlite.database_path = path.into();
        self
    }

    /// Set encryption configuration
    pub fn with_encryption(mut self, encryption: EncryptionConfig) -> Self {
        self.encryption = encryption;
        self
    }

    /// Enable/disable compression
    pub fn with_compression(mut self, enable: bool, level: u32) -> Self {
        self.enable_compression = enable;
        self.compression_level = level.clamp(1, 9);
        self
    }

    /// Set backup configuration
    pub fn with_backup<P: Into<PathBuf>>(
        mut self,
        enable: bool,
        interval_hours: u32,
        max_backups: u32,
        directory: P,
    ) -> Self {
        self.enable_auto_backup = enable;
        self.backup_interval_hours = interval_hours;
        self.max_backups = max_backups;
        self.backup_directory = directory.into();
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> StorageResult<()> {
        // Validate SQLite configuration
        if self.backend == StorageBackend::SQLite {
            if self.sqlite.max_connections == 0 {
                return Err(StorageError::configuration(
                    "SQLite max_connections must be greater than 0",
                ));
            }

            if self.sqlite.connection_timeout == 0 {
                return Err(StorageError::configuration(
                    "SQLite connection_timeout must be greater than 0",
                ));
            }

            if self.sqlite.cache_size <= 0 {
                return Err(StorageError::configuration(
                    "SQLite cache_size must be greater than 0",
                ));
            }

            if self.sqlite.page_size < 512 || self.sqlite.page_size > 65536 {
                return Err(StorageError::configuration(
                    "SQLite page_size must be between 512 and 65536",
                ));
            }

            // Validate database path parent directory exists (skip for in-memory databases)
            if self.sqlite.database_path.to_string_lossy() != ":memory:" {
                if let Some(parent) = self.sqlite.database_path.parent() {
                    if !parent.exists() {
                        return Err(StorageError::configuration(format!(
                            "Database directory does not exist: {}",
                            parent.display()
                        )));
                    }
                }
            }
        }

        // Validate encryption configuration
        if self.encryption.memory_cost < 1024 {
            return Err(StorageError::configuration(
                "Encryption memory_cost must be at least 1024 KB",
            ));
        }

        if self.encryption.time_cost == 0 {
            return Err(StorageError::configuration(
                "Encryption time_cost must be greater than 0",
            ));
        }

        if self.encryption.parallelism == 0 {
            return Err(StorageError::configuration(
                "Encryption parallelism must be greater than 0",
            ));
        }

        // Validate compression level
        if self.enable_compression && (self.compression_level < 1 || self.compression_level > 9) {
            return Err(StorageError::configuration(
                "Compression level must be between 1 and 9",
            ));
        }

        // Validate backup configuration
        if self.enable_auto_backup {
            if self.backup_interval_hours == 0 {
                return Err(StorageError::configuration(
                    "Backup interval must be greater than 0",
                ));
            }

            if self.max_backups == 0 {
                return Err(StorageError::configuration(
                    "Max backups must be greater than 0",
                ));
            }

            // Check if backup directory parent exists
            if let Some(parent) = self.backup_directory.parent() {
                if !parent.exists() {
                    return Err(StorageError::configuration(format!(
                        "Backup directory parent does not exist: {}",
                        parent.display()
                    )));
                }
            }
        }

        Ok(())
    }

    /// Get the database URL for SQLite
    pub fn get_database_url(&self) -> String {
        format!("sqlite:{}", self.sqlite.database_path.display())
    }

    /// Create directories if they don't exist
    pub fn ensure_directories(&self) -> StorageResult<()> {
        // Create database directory (skip for in-memory databases)
        if self.backend == StorageBackend::SQLite && self.sqlite.database_path.to_string_lossy() != ":memory:" {
            if let Some(parent) = self.sqlite.database_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    StorageError::configuration(format!(
                        "Failed to create database directory: {}",
                        e
                    ))
                })?;
            }
        }

        // Create backup directory
        if self.enable_auto_backup {
            std::fs::create_dir_all(&self.backup_directory).map_err(|e| {
                StorageError::configuration(format!("Failed to create backup directory: {}", e))
            })?;
        }

        Ok(())
    }

    /// Load configuration from file
    pub fn load_from_file<P: AsRef<std::path::Path>>(path: P) -> StorageResult<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            StorageError::configuration(format!("Failed to read config file: {}", e))
        })?;

        let config: Self = serde_json::from_str(&content).map_err(|e| {
            StorageError::configuration(format!("Failed to parse config file: {}", e))
        })?;

        config.validate()?;
        Ok(config)
    }

    /// Save configuration to file
    pub fn save_to_file<P: AsRef<std::path::Path>>(&self, path: P) -> StorageResult<()> {
        let content = serde_json::to_string_pretty(self).map_err(|e| {
            StorageError::configuration(format!("Failed to serialize config: {}", e))
        })?;

        std::fs::write(path, content).map_err(|e| {
            StorageError::configuration(format!("Failed to write config file: {}", e))
        })?;

        Ok(())
    }
}
