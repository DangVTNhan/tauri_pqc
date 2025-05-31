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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_vault_master_key_creation() {
        let password = "test_password_123";
        let master_key = VaultMasterKey::new(password).unwrap();

        // Verify basic properties
        assert!(!master_key.id.is_nil());
        assert_eq!(master_key.salt.len(), 32); // SALT_SIZE
        assert_eq!(master_key.version, "1.0");
        assert!(master_key.created_at <= Utc::now());
    }

    #[test]
    fn test_vault_master_key_password_verification() {
        let password = "secure_password_456";
        let master_key = VaultMasterKey::new(password).unwrap();

        // Correct password should verify
        assert!(master_key.verify_password(password));

        // Wrong password should fail
        assert!(!master_key.verify_password("wrong_password"));
        assert!(!master_key.verify_password(""));
        assert!(!master_key.verify_password("secure_password_45")); // Close but wrong
    }

    #[test]
    fn test_vault_master_key_decryption() {
        let password = "decryption_test_789";
        let master_key = VaultMasterKey::new(password).unwrap();

        // Should be able to decrypt with correct password
        let decrypted_key = master_key.decrypt_master_key(password).unwrap();
        assert_eq!(decrypted_key.len(), 32); // AES-256 key size

        // Should fail with wrong password
        assert!(master_key.decrypt_master_key("wrong_password").is_err());
    }

    #[test]
    fn test_vault_master_key_consistency() {
        let password = "consistency_test_abc";
        let master_key = VaultMasterKey::new(password).unwrap();

        // Multiple decryptions should yield the same key
        let key1 = master_key.decrypt_master_key(password).unwrap();
        let key2 = master_key.decrypt_master_key(password).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_vault_metadata_creation() {
        let name = "Test Vault".to_string();
        let path = PathBuf::from("/tmp/test_vault");
        let metadata = VaultMetadata::new(name.clone(), path.clone());

        assert_eq!(metadata.name, name);
        assert_eq!(metadata.directory_path, path);
        assert!(!metadata.id.is_nil());
        assert_eq!(metadata.version, "1.0");
        assert!(metadata.last_accessed.is_none());
        assert_eq!(metadata.file_hierarchy.total_files, 0);
        assert_eq!(metadata.file_hierarchy.total_directories, 0);
        assert_eq!(metadata.file_hierarchy.total_size, 0);
    }

    #[test]
    fn test_vault_metadata_access_tracking() {
        let name = "Access Test Vault".to_string();
        let path = PathBuf::from("/tmp/access_test");
        let mut metadata = VaultMetadata::new(name, path);

        // Initially no access time
        assert!(metadata.last_accessed.is_none());

        // Mark as accessed
        let before_access = Utc::now();
        metadata.mark_accessed();
        let after_access = Utc::now();

        // Should have access time set
        assert!(metadata.last_accessed.is_some());
        let access_time = metadata.last_accessed.unwrap();
        assert!(access_time >= before_access && access_time <= after_access);
    }

    #[test]
    fn test_file_hierarchy_initialization() {
        let hierarchy = FileHierarchy::new();

        assert!(hierarchy.root_entries.is_empty());
        assert_eq!(hierarchy.total_files, 0);
        assert_eq!(hierarchy.total_directories, 0);
        assert_eq!(hierarchy.total_size, 0);
    }

    #[test]
    fn test_vault_settings_defaults() {
        let settings = VaultSettings::default();

        assert_eq!(settings.auto_lock_timeout, Some(30));
        assert!(settings.compression_enabled);
        assert_eq!(settings.max_file_size, Some(100 * 1024 * 1024)); // 100MB
        assert!(settings.allowed_extensions.is_empty());
    }

    #[test]
    fn test_key_derivation_params_defaults() {
        let params = KeyDerivationParams::default();

        assert_eq!(params.memory_cost, 65536); // 64 MB
        assert_eq!(params.time_cost, 3);
        assert_eq!(params.parallelism, 4);
    }

    #[test]
    fn test_key_derivation_params_to_encryption_config() {
        let params = KeyDerivationParams {
            memory_cost: 32768,
            time_cost: 2,
            parallelism: 2,
        };

        let config = params.to_encryption_config();
        assert_eq!(config.memory_cost, 32768);
        assert_eq!(config.time_cost, 2);
        assert_eq!(config.parallelism, 2);
    }

    #[test]
    fn test_create_vault_request_serialization() {
        let request = CreateVaultRequest {
            name: "Serialization Test".to_string(),
            path: "/tmp/test".to_string(),
            password: "test_password".to_string(),
        };

        // Should serialize and deserialize correctly
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: CreateVaultRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request.name, deserialized.name);
        assert_eq!(request.path, deserialized.path);
        assert_eq!(request.password, deserialized.password);
    }

    #[test]
    fn test_vault_entry_types() {
        // Test VaultEntryType serialization
        let file_type = VaultEntryType::File;
        let dir_type = VaultEntryType::Directory;

        let file_json = serde_json::to_string(&file_type).unwrap();
        let dir_json = serde_json::to_string(&dir_type).unwrap();

        assert_eq!(file_json, "\"File\"");
        assert_eq!(dir_json, "\"Directory\"");

        // Test deserialization
        let file_deserialized: VaultEntryType = serde_json::from_str(&file_json).unwrap();
        let dir_deserialized: VaultEntryType = serde_json::from_str(&dir_json).unwrap();

        assert!(matches!(file_deserialized, VaultEntryType::File));
        assert!(matches!(dir_deserialized, VaultEntryType::Directory));
    }

    #[test]
    fn test_vault_entry_creation() {
        let entry = VaultEntry {
            id: Uuid::new_v4(),
            encrypted_name: b"encrypted_file_name".to_vec(),
            entry_type: VaultEntryType::File,
            size: Some(1024),
            created_at: Utc::now(),
            modified_at: Utc::now(),
            children: None,
            encryption_metadata: Some(FileEncryptionInfo {
                encrypted_path: "encrypted/path/file.enc".to_string(),
                original_checksum: vec![1, 2, 3, 4],
                nonce: vec![5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                compression: Some("gzip".to_string()),
            }),
        };

        assert!(!entry.id.is_nil());
        assert_eq!(entry.encrypted_name, b"encrypted_file_name");
        assert!(matches!(entry.entry_type, VaultEntryType::File));
        assert_eq!(entry.size, Some(1024));
        assert!(entry.children.is_none());
        assert!(entry.encryption_metadata.is_some());
    }

    #[test]
    fn test_different_passwords_produce_different_keys() {
        let password1 = "password_one";
        let password2 = "password_two";

        let master_key1 = VaultMasterKey::new(password1).unwrap();
        let master_key2 = VaultMasterKey::new(password2).unwrap();

        // Different passwords should produce different encrypted master keys
        assert_ne!(master_key1.encrypted_master_key.ciphertext,
                  master_key2.encrypted_master_key.ciphertext);

        // Different salts should be generated
        assert_ne!(master_key1.salt, master_key2.salt);
    }

    #[test]
    fn test_vault_master_key_serialization() {
        let password = "serialization_test";
        let master_key = VaultMasterKey::new(password).unwrap();

        // Should serialize and deserialize correctly
        let json = serde_json::to_string(&master_key).unwrap();
        let deserialized: VaultMasterKey = serde_json::from_str(&json).unwrap();

        assert_eq!(master_key.id, deserialized.id);
        assert_eq!(master_key.salt, deserialized.salt);
        assert_eq!(master_key.version, deserialized.version);
        assert_eq!(master_key.created_at, deserialized.created_at);

        // Deserialized key should still verify the password
        assert!(deserialized.verify_password(password));
    }
}
