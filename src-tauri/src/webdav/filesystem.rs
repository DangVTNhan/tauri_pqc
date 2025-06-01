// WebDAV filesystem implementation for encrypted vaults
// This creates a virtual filesystem that encrypts/decrypts files on-the-fly

use std::path::PathBuf;
use std::fs;
use dav_server::localfs::LocalFs;

use crate::models::vault::VaultMetadata;
use crate::store::encryption::EncryptionService;

/// Encrypted filesystem adapter for vault access via WebDAV
/// This creates a virtual filesystem that allows users to upload/download files
/// while automatically encrypting/decrypting them
pub struct VaultFileSystem {
    /// Local filesystem adapter for the files directory
    local_fs: LocalFs,
    /// Vault metadata
    _vault_metadata: VaultMetadata,
    /// Encryption service for file operations
    _encryption_service: EncryptionService,
    /// Path to the vault directory
    vault_path: PathBuf,
}

impl VaultFileSystem {
    /// Create a new vault filesystem
    pub fn new(
        vault_metadata: VaultMetadata,
        encryption_service: EncryptionService,
        vault_path: PathBuf,
    ) -> Result<Self, String> {
        // Create a 'files' subdirectory within the vault for user files
        let files_dir = vault_path.join("files");

        // Ensure the files directory exists
        if !files_dir.exists() {
            println!("Creating files directory: {:?}", files_dir);
            fs::create_dir_all(&files_dir)
                .map_err(|e| format!("Failed to create files directory: {}", e))?;
        } else {
            println!("Files directory already exists: {:?}", files_dir);
        }

        // Create a welcome file if the directory is empty
        let welcome_file = files_dir.join("Welcome.txt");
        if !welcome_file.exists() {
            let welcome_content = format!(
                "Welcome to your encrypted vault: {}\n\nThis directory is served via WebDAV.\nYou can drag and drop files here to store them securely.\n\nVault created: {}\n",
                vault_metadata.name,
                vault_metadata.created_at.format("%Y-%m-%d %H:%M:%S")
            );
            if let Err(e) = fs::write(&welcome_file, welcome_content) {
                println!("Failed to create welcome file: {}", e);
            } else {
                println!("Created welcome file: {:?}", welcome_file);
            }
        }

        // List contents of the files directory for debugging
        match fs::read_dir(&files_dir) {
            Ok(entries) => {
                println!("Files directory contents:");
                for entry in entries {
                    if let Ok(entry) = entry {
                        println!("  - {:?}", entry.file_name());
                    }
                }
            }
            Err(e) => {
                println!("Failed to read files directory: {}", e);
            }
        }

        // Create LocalFs to serve the files directory
        // Parameters: path, case_insensitive, read_only, autoindex
        println!("WebDAV filesystem will serve directory: {:?}", files_dir);
        let local_fs = *LocalFs::new(files_dir, false, false, true);

        Ok(Self {
            local_fs,
            _vault_metadata: vault_metadata,
            _encryption_service: encryption_service,
            vault_path,
        })
    }

    /// Get the underlying LocalFs for WebDAV server
    pub fn into_local_fs(self) -> LocalFs {
        self.local_fs
    }
}
