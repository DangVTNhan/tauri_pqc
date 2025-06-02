// WebDAV filesystem implementation for encrypted vaults
// This creates a virtual filesystem that encrypts/decrypts files on-the-fly

use std::path::PathBuf;
use std::fs;
use dav_server::localfs::LocalFs;

use crate::models::vault::VaultMetadata;
use crate::store::encryption::EncryptionService;
use super::encrypted_filesystem::EncryptedFileSystem;

/// Encrypted filesystem adapter for vault access via WebDAV
/// This creates a virtual filesystem that allows users to upload/download files
/// while automatically encrypting/decrypting them
pub struct VaultFileSystem {
    /// Encrypted filesystem for in-memory decryption
    encrypted_fs: EncryptedFileSystem,
    /// Vault metadata
    _vault_metadata: VaultMetadata,
    /// Encryption service for file operations
    _encryption_service: EncryptionService,
    /// Path to the vault directory
    vault_path: PathBuf,
}

impl VaultFileSystem {
    /// Create a new vault filesystem
    pub async fn new(
        vault_metadata: VaultMetadata,
        encryption_service: EncryptionService,
        vault_path: PathBuf,
    ) -> Result<Self, String> {
        // Create the encrypted filesystem for in-memory decryption
        let encrypted_fs = EncryptedFileSystem::new(
            vault_metadata.clone(),
            encryption_service.clone(),
            vault_path.clone(),
        ).await?;

        println!("Created encrypted filesystem for vault: {}", vault_metadata.name);

        Ok(Self {
            encrypted_fs,
            _vault_metadata: vault_metadata,
            _encryption_service: encryption_service,
            vault_path,
        })
    }

    /// Get the encrypted filesystem for WebDAV server
    pub fn into_encrypted_fs(self) -> EncryptedFileSystem {
        self.encrypted_fs
    }

    /// Clear the filesystem cache (used when locking vault)
    pub async fn clear_cache(&self) {
        self.encrypted_fs.clear_cache().await;
    }

    /// Legacy method for compatibility - returns a LocalFs that serves an empty directory
    /// This is kept for backward compatibility but should not be used for encrypted vaults
    #[deprecated(note = "Use into_encrypted_fs() instead for encrypted vault access")]
    pub fn into_local_fs(self) -> LocalFs {
        // Create a temporary empty directory for compatibility
        let temp_dir = std::env::temp_dir().join("empty_vault");
        let _ = fs::create_dir_all(&temp_dir);
        *LocalFs::new(temp_dir, false, true, false) // read-only empty directory
    }
}
