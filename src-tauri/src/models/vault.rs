use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use crate::store::encryption::{EncryptedData, EncryptionService};
use crate::store::error::StorageResult;

/// Master key file structure for vault encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMasterKey {
    /// Unique identifier for this master key
    pub id: Uuid,
    /// Salt used for password-based key derivation
    pub salt: Vec<u8>,
    /// Encrypted master key (encrypted with user password)
    pub encrypted_master_key: EncryptedData,
    /// Key derivation parameters
    pub key_derivation_params: KeyDerivationParams,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Version for future compatibility
    pub version: String,
}

impl VaultMasterKey {
    /// Create a new vault master key from user password
    pub fn new(password: &str) -> StorageResult<Self> {
        // Generate random salt for password derivation
        let salt = EncryptionService::generate_salt();

        // Generate random master key (32 bytes for AES-256)
        let mut master_key = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut master_key);

        // Derive key from password using the salt
        let password_key = EncryptionService::with_password(
            password,
            &salt,
            Default::default()
        )?;

        // Encrypt the master key with the password-derived key
        let encrypted_master_key = password_key.encrypt(&master_key)?;

        Ok(Self {
            id: Uuid::new_v4(),
            salt: salt.to_vec(),
            encrypted_master_key,
            key_derivation_params: KeyDerivationParams::default(),
            created_at: Utc::now(),
            version: "1.0".to_string(),
        })
    }

    /// Decrypt the master key using user password
    pub fn decrypt_master_key(&self, password: &str) -> StorageResult<Vec<u8>> {
        let password_key = EncryptionService::with_password(
            password,
            &self.salt,
            self.key_derivation_params.to_encryption_config(),
        )?;

        password_key.decrypt(&self.encrypted_master_key)
    }

    /// Verify password by attempting to decrypt master key
    pub fn verify_password(&self, password: &str) -> bool {
        self.decrypt_master_key(password).is_ok()
    }
}

/// Vault configuration metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMetadata {
    /// Unique identifier for this vault
    pub id: Uuid,
    /// Display name of the vault
    pub name: String,
    /// Vault directory path
    pub directory_path: PathBuf,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last accessed timestamp
    pub last_accessed: Option<DateTime<Utc>>,
    /// File and folder hierarchy information
    pub file_hierarchy: FileHierarchy,
    /// Vault settings
    pub settings: VaultSettings,
    /// Version for future compatibility
    pub version: String,
}

impl VaultMetadata {
    /// Create new vault metadata
    pub fn new(name: String, directory_path: PathBuf) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            directory_path,
            created_at: Utc::now(),
            last_accessed: None,
            file_hierarchy: FileHierarchy::new(),
            settings: VaultSettings::default(),
            version: "1.0".to_string(),
        }
    }

    /// Mark vault as accessed
    pub fn mark_accessed(&mut self) {
        self.last_accessed = Some(Utc::now());
    }
}

/// File and folder hierarchy within the vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHierarchy {
    /// Root directory entries
    pub root_entries: Vec<VaultEntry>,
    /// Total number of files
    pub total_files: u64,
    /// Total number of directories
    pub total_directories: u64,
    /// Total size in bytes
    pub total_size: u64,
}

impl FileHierarchy {
    pub fn new() -> Self {
        Self {
            root_entries: Vec::new(),
            total_files: 0,
            total_directories: 0,
            total_size: 0,
        }
    }
}

/// Entry in the vault (file or directory)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    /// Unique identifier
    pub id: Uuid,
    /// Entry name (encrypted)
    pub encrypted_name: Vec<u8>,
    /// Entry type
    pub entry_type: VaultEntryType,
    /// Size in bytes (for files)
    pub size: Option<u64>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modified timestamp
    pub modified_at: DateTime<Utc>,
    /// Child entries (for directories)
    pub children: Option<Vec<VaultEntry>>,
    /// File encryption metadata (for files)
    pub encryption_metadata: Option<FileEncryptionInfo>,
}

/// Type of vault entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultEntryType {
    File,
    Directory,
}

/// File encryption information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEncryptionInfo {
    /// Encrypted file path within vault
    pub encrypted_path: String,
    /// Original file checksum
    pub original_checksum: Vec<u8>,
    /// Encryption nonce
    pub nonce: Vec<u8>,
    /// Compression used (if any)
    pub compression: Option<String>,
}

/// Vault settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSettings {
    /// Auto-lock timeout in minutes
    pub auto_lock_timeout: Option<u32>,
    /// Compression enabled
    pub compression_enabled: bool,
    /// Maximum file size in bytes
    pub max_file_size: Option<u64>,
    /// Allowed file extensions (empty = all allowed)
    pub allowed_extensions: Vec<String>,
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            auto_lock_timeout: Some(30), // 30 minutes
            compression_enabled: true,
            max_file_size: Some(100 * 1024 * 1024), // 100MB
            allowed_extensions: Vec::new(), // Allow all
        }
    }
}

/// Key derivation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationParams {
    /// Memory cost for Argon2
    pub memory_cost: u32,
    /// Time cost for Argon2
    pub time_cost: u32,
    /// Parallelism for Argon2
    pub parallelism: u32,
}

impl Default for KeyDerivationParams {
    fn default() -> Self {
        Self {
            memory_cost: 65536, // 64 MB
            time_cost: 3,       // 3 iterations
            parallelism: 4,     // 4 threads
        }
    }
}

impl KeyDerivationParams {
    pub fn to_encryption_config(&self) -> crate::store::encryption::EncryptionConfig {
        crate::store::encryption::EncryptionConfig {
            memory_cost: self.memory_cost,
            time_cost: self.time_cost,
            parallelism: self.parallelism,
        }
    }
}

/// Request structure for creating a new vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVaultRequest {
    /// Vault name
    pub name: String,
    /// Parent directory path where vault will be created
    pub path: String,
    /// Vault password
    pub password: String,
}

/// Response structure for vault creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVaultResponse {
    /// Created vault configuration
    pub vault_config: crate::models::config::VaultConfig,
    /// Success message
    pub message: String,
}
