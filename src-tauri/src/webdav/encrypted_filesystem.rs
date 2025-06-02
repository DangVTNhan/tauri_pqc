// Encrypted filesystem implementation for WebDAV
// This provides in-memory decryption of vault files for WebDAV access

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use std::pin::Pin;
use std::io::{self, SeekFrom};

use tokio::sync::RwLock;
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite};
use bytes::{Bytes, Buf};
use dav_server::fs::{
    DavFileSystem, DavFile, DavDirEntry, DavMetaData,
    FsFuture, FsError
};
use dav_server::davpath::DavPath;
use futures_util::stream::{self, StreamExt};

use crate::models::vault::VaultMetadata;
use crate::store::encryption::{EncryptionService, EncryptedData};

/// In-memory file representation for decrypted content
#[derive(Debug, Clone)]
struct DecryptedFile {
    /// Original file name
    name: String,
    /// Decrypted content
    content: Bytes,
    /// File size
    size: u64,
    /// Last modified time
    modified: SystemTime,
    /// Whether this is a directory
    is_dir: bool,
}

/// Encrypted filesystem that serves decrypted content in-memory via WebDAV
#[derive(Debug)]
pub struct EncryptedFileSystem {
    /// Vault metadata
    vault_metadata: VaultMetadata,
    /// Encryption service for decrypting files
    encryption_service: EncryptionService,
    /// Path to the vault directory on disk
    vault_path: PathBuf,
    /// In-memory cache of decrypted files (path -> DecryptedFile)
    file_cache: Arc<RwLock<HashMap<String, DecryptedFile>>>,
}

impl EncryptedFileSystem {
    /// Create a new encrypted filesystem
    pub async fn new(
        vault_metadata: VaultMetadata,
        encryption_service: EncryptionService,
        vault_path: PathBuf,
    ) -> Result<Self, String> {
        let filesystem = Self {
            vault_metadata,
            encryption_service,
            vault_path,
            file_cache: Arc::new(RwLock::new(HashMap::new())),
        };

        // Initialize the filesystem by loading and decrypting all files
        // This must complete before we return the filesystem
        filesystem.initialize_cache().await?;
        println!("Successfully initialized encrypted filesystem cache");

        Ok(filesystem)
    }

    /// Initialize the file cache by loading and decrypting all files from the vault
    async fn initialize_cache(&self) -> Result<(), String> {
        let files_dir = self.vault_path.join("files");

        println!("Initializing encrypted filesystem cache for vault: {}", self.vault_metadata.name);
        println!("Files directory: {:?}", files_dir);

        // Create files directory if it doesn't exist
        if !files_dir.exists() {
            println!("Creating files directory: {:?}", files_dir);
            std::fs::create_dir_all(&files_dir)
                .map_err(|e| format!("Failed to create files directory: {}", e))?;
        }

        // Create welcome file if directory is empty
        self.ensure_welcome_file(&files_dir).await?;

        // Load and decrypt all files
        self.load_encrypted_files(&files_dir, "").await?;

        // Print cache contents for debugging
        let cache = self.file_cache.read().await;
        println!("Cache initialized with {} entries:", cache.len());
        for (path, file) in cache.iter() {
            println!("  - '{}': {} bytes ({})", path, file.size, if file.is_dir { "dir" } else { "file" });
        }

        Ok(())
    }

    /// Ensure welcome file exists
    async fn ensure_welcome_file(&self, files_dir: &Path) -> Result<(), String> {
        let welcome_file = files_dir.join("Welcome.txt");
        if !welcome_file.exists() {
            let welcome_content = format!(
                "Welcome to your encrypted vault: {}\n\nThis directory is served via WebDAV.\nYou can drag and drop files here to store them securely.\n\nVault created: {}\n",
                self.vault_metadata.name,
                self.vault_metadata.created_at.format("%Y-%m-%d %H:%M:%S")
            );

            // Encrypt and store the welcome file
            let encrypted_content = self.encryption_service.encrypt(welcome_content.as_bytes())
                .map_err(|e| format!("Failed to encrypt welcome file: {}", e))?;

            let encrypted_json = serde_json::to_vec(&encrypted_content)
                .map_err(|e| format!("Failed to serialize encrypted welcome file: {}", e))?;

            std::fs::write(&welcome_file, encrypted_json)
                .map_err(|e| format!("Failed to write welcome file: {}", e))?;

            // Add to cache
            let content_bytes = Bytes::from(welcome_content.clone());
            let content_len = welcome_content.len() as u64;
            let mut cache = self.file_cache.write().await;
            cache.insert("Welcome.txt".to_string(), DecryptedFile {
                name: "Welcome.txt".to_string(),
                content: content_bytes,
                size: content_len,
                modified: SystemTime::now(),
                is_dir: false,
            });
        }

        Ok(())
    }

    /// Recursively load and decrypt files from the vault directory
    fn load_encrypted_files<'a>(&'a self, dir: &'a Path, relative_path: &'a str) -> Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
        let entries = std::fs::read_dir(dir)
            .map_err(|e| format!("Failed to read directory {}: {}", dir.display(), e))?;

        for entry in entries {
            let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();
            
            let cache_path = if relative_path.is_empty() {
                file_name.clone()
            } else {
                format!("{}/{}", relative_path, file_name)
            };

            if path.is_dir() {
                // Add directory to cache
                let mut cache = self.file_cache.write().await;
                cache.insert(cache_path.clone(), DecryptedFile {
                    name: file_name.clone(),
                    content: Bytes::new(),
                    size: 0,
                    modified: entry.metadata()
                        .and_then(|m| m.modified())
                        .unwrap_or(SystemTime::now()),
                    is_dir: true,
                });
                drop(cache);

                // Recursively load subdirectory
                Box::pin(self.load_encrypted_files(&path, &cache_path)).await?;
            } else {
                // Load and decrypt file
                self.load_and_decrypt_file(&path, &cache_path).await?;
            }
        }

        Ok(())
        })
    }

    /// Load and decrypt a single file
    async fn load_and_decrypt_file(&self, file_path: &Path, cache_path: &str) -> Result<(), String> {
        println!("Loading and decrypting file: {} -> {}", file_path.display(), cache_path);

        // Read encrypted file
        let encrypted_data = std::fs::read(file_path)
            .map_err(|e| format!("Failed to read file {}: {}", file_path.display(), e))?;

        println!("Read {} bytes from disk for file: {}", encrypted_data.len(), cache_path);

        // Try to deserialize as encrypted data
        let decrypted_content = match serde_json::from_slice::<EncryptedData>(&encrypted_data) {
            Ok(encrypted) => {
                // File is encrypted, decrypt it
                println!("File {} is encrypted, decrypting...", cache_path);
                let decrypted = self.encryption_service.decrypt(&encrypted)
                    .map_err(|e| format!("Failed to decrypt file {}: {}", file_path.display(), e))?;
                println!("Successfully decrypted {} bytes for file: {}", decrypted.len(), cache_path);
                decrypted
            }
            Err(_) => {
                // File is not encrypted (legacy or plain text), use as-is
                println!("File {} is not encrypted, using as-is", cache_path);
                encrypted_data
            }
        };

        // Get file metadata for modification time
        let metadata = std::fs::metadata(file_path)
            .map_err(|e| format!("Failed to get metadata for {}: {}", file_path.display(), e))?;

        // Add to cache - use decrypted content size, not encrypted file size
        let content_bytes = Bytes::from(decrypted_content);
        let content_size = content_bytes.len() as u64;

        let mut cache = self.file_cache.write().await;
        cache.insert(cache_path.to_string(), DecryptedFile {
            name: file_path.file_name().unwrap().to_string_lossy().to_string(),
            content: content_bytes,
            size: content_size,
            modified: metadata.modified().unwrap_or(SystemTime::now()),
            is_dir: false,
        });

        println!("Added file '{}' to cache: {} bytes", cache_path, content_size);

        Ok(())
    }

    /// Clear all cached files (used when locking vault)
    pub async fn clear_cache(&self) {
        let mut cache = self.file_cache.write().await;
        cache.clear();
    }
}

impl Clone for EncryptedFileSystem {
    fn clone(&self) -> Self {
        Self {
            vault_metadata: self.vault_metadata.clone(),
            encryption_service: self.encryption_service.clone(),
            vault_path: self.vault_path.clone(),
            file_cache: Arc::clone(&self.file_cache),
        }
    }
}

/// In-memory file handle for decrypted content
#[derive(Debug)]
struct DecryptedFileHandle {
    content: Bytes,
    position: u64,
    /// Path to the file for writing back to disk
    file_path: String,
    /// Reference to the filesystem for write operations
    filesystem: EncryptedFileSystem,
    /// Whether the file has been modified
    modified: bool,
}

impl DecryptedFileHandle {
    fn new(content: Bytes, file_path: String, filesystem: EncryptedFileSystem) -> Self {
        Self {
            content,
            position: 0,
            file_path,
            filesystem,
            modified: false,
        }
    }

    /// Save the file content back to disk (encrypted)
    async fn save_to_disk(&self) -> Result<(), String> {
        if !self.modified {
            return Ok(());
        }

        println!("Saving file '{}' to disk ({} bytes)", self.file_path, self.content.len());

        // Encrypt the content
        let encrypted_data = self.filesystem.encryption_service.encrypt(&self.content)
            .map_err(|e| format!("Failed to encrypt file: {}", e))?;

        // Serialize the encrypted data
        let encrypted_json = serde_json::to_vec(&encrypted_data)
            .map_err(|e| format!("Failed to serialize encrypted data: {}", e))?;

        // Write to disk
        let disk_path = self.filesystem.vault_path.join("files").join(&self.file_path);

        // Ensure parent directory exists
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create parent directory: {}", e))?;
        }

        std::fs::write(&disk_path, encrypted_json)
            .map_err(|e| format!("Failed to write file to disk: {}", e))?;

        println!("Successfully saved encrypted file to: {:?}", disk_path);

        // Update the cache
        let mut cache = self.filesystem.file_cache.write().await;
        cache.insert(self.file_path.clone(), DecryptedFile {
            name: std::path::Path::new(&self.file_path)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            content: self.content.clone(),
            size: self.content.len() as u64,
            modified: std::time::SystemTime::now(),
            is_dir: false,
        });

        println!("Updated cache for file: {}", self.file_path);

        Ok(())
    }
}

impl AsyncRead for DecryptedFileHandle {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let remaining = self.content.len() as u64 - self.position;
        if remaining == 0 {
            return std::task::Poll::Ready(Ok(()));
        }

        let start = self.position as usize;
        let end = std::cmp::min(start + buf.remaining(), self.content.len());
        let to_read = &self.content[start..end];

        buf.put_slice(to_read);
        self.position += (end - start) as u64;

        std::task::Poll::Ready(Ok(()))
    }
}

impl AsyncSeek for DecryptedFileHandle {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        let new_pos = match position {
            SeekFrom::Start(pos) => pos,
            SeekFrom::End(offset) => {
                let len = self.content.len() as i64;
                (len + offset) as u64
            }
            SeekFrom::Current(offset) => {
                let current = self.position as i64;
                (current + offset) as u64
            }
        };

        if new_pos > self.content.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Seek position beyond end of file",
            ));
        }

        self.position = new_pos;
        Ok(())
    }

    fn poll_complete(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<u64>> {
        std::task::Poll::Ready(Ok(self.position))
    }
}

impl AsyncWrite for DecryptedFileHandle {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        // For now, we don't support writing to encrypted files
        std::task::Poll::Ready(Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Writing to encrypted files not yet supported",
        )))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl DavFile for DecryptedFileHandle {
    fn metadata(&mut self) -> FsFuture<Box<dyn DavMetaData>> {
        let size = self.content.len() as u64;
        Box::pin(async move {
            Ok(Box::new(DecryptedFileMetadata {
                size,
                modified: SystemTime::now(),
                is_dir: false,
            }) as Box<dyn DavMetaData>)
        })
    }

    fn write_buf(&mut self, mut buf: Box<dyn Buf + Send + 'static>) -> FsFuture<()> {
        // Convert Buf to Bytes
        let mut bytes_vec = Vec::new();
        while buf.has_remaining() {
            let chunk = buf.chunk();
            bytes_vec.extend_from_slice(chunk);
            let len = chunk.len();
            buf.advance(len);
        }
        let bytes = Bytes::from(bytes_vec);

        // Use write_bytes implementation
        self.write_bytes(bytes)
    }

    fn write_bytes(&mut self, buf: Bytes) -> FsFuture<()> {
        println!("Writing {} bytes to file '{}'", buf.len(), self.file_path);

        // Replace content at current position
        let mut new_content = Vec::new();

        // Keep content before current position
        if self.position > 0 {
            let before_len = std::cmp::min(self.position as usize, self.content.len());
            new_content.extend_from_slice(&self.content[..before_len]);
        }

        // Add new content
        new_content.extend_from_slice(&buf);

        // Add content after the written section (if any)
        let after_start = self.position as usize + buf.len();
        if after_start < self.content.len() {
            new_content.extend_from_slice(&self.content[after_start..]);
        }

        // Update content and position
        self.content = Bytes::from(new_content);
        self.position += buf.len() as u64;
        self.modified = true;

        println!("File '{}' now has {} bytes, position: {}", self.file_path, self.content.len(), self.position);

        Box::pin(async move {
            Ok(())
        })
    }

    fn read_bytes(&mut self, count: usize) -> FsFuture<Bytes> {
        let start = self.position as usize;
        let end = std::cmp::min(start + count, self.content.len());
        let result = self.content.slice(start..end);
        self.position = end as u64;

        Box::pin(async move {
            Ok(result)
        })
    }

    fn seek(&mut self, pos: SeekFrom) -> FsFuture<u64> {
        let new_pos = match pos {
            SeekFrom::Start(pos) => pos,
            SeekFrom::End(offset) => {
                let len = self.content.len() as i64;
                (len + offset) as u64
            }
            SeekFrom::Current(offset) => {
                let current = self.position as i64;
                (current + offset) as u64
            }
        };

        if new_pos > self.content.len() as u64 {
            Box::pin(async move {
                Err(FsError::GeneralFailure)
            })
        } else {
            self.position = new_pos;
            Box::pin(async move {
                Ok(new_pos)
            })
        }
    }

    fn flush(&mut self) -> FsFuture<()> {
        let filesystem = self.filesystem.clone();
        let file_path = self.file_path.clone();
        let content = self.content.clone();
        let modified = self.modified;

        Box::pin(async move {
            if modified {
                println!("Flushing file '{}' to disk", file_path);

                // Create a temporary handle to save the file
                let temp_handle = DecryptedFileHandle {
                    content,
                    position: 0,
                    file_path,
                    filesystem,
                    modified: true,
                };

                temp_handle.save_to_disk().await
                    .map_err(|e| {
                        eprintln!("Failed to save file during flush: {}", e);
                        FsError::GeneralFailure
                    })?;
            }
            Ok(())
        })
    }
}

/// Metadata for decrypted files
#[derive(Debug, Clone)]
struct DecryptedFileMetadata {
    size: u64,
    modified: SystemTime,
    is_dir: bool,
}

impl DavMetaData for DecryptedFileMetadata {
    fn len(&self) -> u64 {
        self.size
    }

    fn modified(&self) -> Result<SystemTime, FsError> {
        Ok(self.modified)
    }

    fn is_dir(&self) -> bool {
        self.is_dir
    }
}

/// Directory entry for decrypted files
struct DecryptedDirEntry {
    name: String,
    metadata: DecryptedFileMetadata,
}

impl DavDirEntry for DecryptedDirEntry {
    fn name(&self) -> Vec<u8> {
        self.name.as_bytes().to_vec()
    }

    fn metadata(&self) -> FsFuture<Box<dyn DavMetaData>> {
        let metadata = DecryptedFileMetadata {
            size: self.metadata.size,
            modified: self.metadata.modified,
            is_dir: self.metadata.is_dir,
        };
        Box::pin(async move {
            Ok(Box::new(metadata) as Box<dyn DavMetaData>)
        })
    }
}

impl DavFileSystem for EncryptedFileSystem {
    fn open<'a>(
        &'a self,
        path: &'a DavPath,
        options: dav_server::fs::OpenOptions,
    ) -> FsFuture<'a, Box<dyn DavFile>> {
        Box::pin(async move {
            let path_str = path.as_url_string();

            println!("WebDAV open for path: '{}' with options: {:?}", path_str, options);

            // Normalize path
            let normalized_path = if path_str == "/" || path_str.is_empty() {
                return Err(dav_server::fs::FsError::Forbidden); // Can't open root as file
            } else {
                path_str.trim_start_matches('/')
            };

            let cache = self.file_cache.read().await;

            if let Some(file) = cache.get(normalized_path) {
                if file.is_dir {
                    println!("Cannot open directory '{}' as file", normalized_path);
                    return Err(dav_server::fs::FsError::Forbidden);
                }

                println!("Opening existing file '{}' ({} bytes)", normalized_path, file.size);
                let handle = DecryptedFileHandle::new(
                    file.content.clone(),
                    normalized_path.to_string(),
                    self.clone(),
                );
                Ok(Box::new(handle) as Box<dyn DavFile>)
            } else if options.write {
                // Create new file
                println!("Creating new file '{}'", normalized_path);
                drop(cache); // Release read lock

                // Add empty file to cache
                let mut cache = self.file_cache.write().await;
                cache.insert(normalized_path.to_string(), DecryptedFile {
                    name: std::path::Path::new(normalized_path)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    content: Bytes::new(),
                    size: 0,
                    modified: std::time::SystemTime::now(),
                    is_dir: false,
                });
                drop(cache);

                let handle = DecryptedFileHandle::new(
                    Bytes::new(),
                    normalized_path.to_string(),
                    self.clone(),
                );
                Ok(Box::new(handle) as Box<dyn DavFile>)
            } else {
                println!("File '{}' not found in cache", normalized_path);
                Err(dav_server::fs::FsError::NotFound)
            }
        })
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        _meta: dav_server::fs::ReadDirMeta,
    ) -> FsFuture<'a, dav_server::fs::FsStream<Box<dyn DavDirEntry>>> {
        Box::pin(async move {
            let path_str = path.as_url_string();
            let cache = self.file_cache.read().await;

            println!("WebDAV read_dir for path: '{}'", path_str);

            // Normalize path - root path should be empty string
            let normalized_path = if path_str == "/" || path_str.is_empty() {
                ""
            } else {
                path_str.trim_start_matches('/')
            };

            println!("Normalized path: '{}'", normalized_path);

            // For root directory, we don't need to check if it exists in cache
            // For other directories, check if they exist
            if !normalized_path.is_empty() {
                if let Some(dir) = cache.get(normalized_path) {
                    if !dir.is_dir {
                        println!("Path '{}' is not a directory", normalized_path);
                        return Err(dav_server::fs::FsError::NotFound);
                    }
                } else {
                    println!("Directory '{}' not found in cache", normalized_path);
                    return Err(dav_server::fs::FsError::NotFound);
                }
            }

            // Find all entries that are direct children of this directory
            let mut entries = Vec::new();
            let prefix = if normalized_path.is_empty() {
                String::new()
            } else {
                format!("{}/", normalized_path)
            };

            println!("Looking for children with prefix: '{}'", prefix);

            for (file_path, file) in cache.iter() {
                println!("Checking file: '{}' against prefix: '{}'", file_path, prefix);

                // Skip the directory itself
                if file_path == normalized_path {
                    continue;
                }

                // Check if this is a direct child
                let relative_path = if prefix.is_empty() {
                    // Root directory - all top-level files
                    if file_path.contains('/') {
                        continue; // Skip subdirectory contents
                    }
                    file_path.as_str()
                } else if file_path.starts_with(&prefix) {
                    &file_path[prefix.len()..]
                } else {
                    continue;
                };

                // Skip if this is not a direct child (contains more slashes)
                if relative_path.contains('/') {
                    continue;
                }

                println!("Adding entry: '{}' ({})", file.name, if file.is_dir { "dir" } else { "file" });

                entries.push(Box::new(DecryptedDirEntry {
                    name: file.name.clone(),
                    metadata: DecryptedFileMetadata {
                        size: file.size,
                        modified: file.modified,
                        is_dir: file.is_dir,
                    },
                }) as Box<dyn DavDirEntry>);
            }

            println!("Found {} entries for path '{}'", entries.len(), normalized_path);

            Ok(Box::pin(stream::iter(entries.into_iter().map(Ok))) as dav_server::fs::FsStream<Box<dyn DavDirEntry>>)
        })
    }

    fn metadata<'a>(
        &'a self,
        path: &'a DavPath,
    ) -> FsFuture<'a, Box<dyn DavMetaData>> {
        Box::pin(async move {
            let path_str = path.as_url_string();
            let cache = self.file_cache.read().await;

            println!("WebDAV metadata for path: '{}'", path_str);

            // Handle root directory specially
            if path_str == "/" || path_str.is_empty() {
                println!("Returning metadata for root directory");
                return Ok(Box::new(DecryptedFileMetadata {
                    size: 0,
                    modified: SystemTime::now(),
                    is_dir: true,
                }) as Box<dyn DavMetaData>);
            }

            // Normalize path
            let normalized_path = path_str.trim_start_matches('/');

            if let Some(file) = cache.get(normalized_path) {
                println!("Found metadata for '{}': {} bytes, {}", normalized_path, file.size, if file.is_dir { "dir" } else { "file" });
                Ok(Box::new(DecryptedFileMetadata {
                    size: file.size,
                    modified: file.modified,
                    is_dir: file.is_dir,
                }) as Box<dyn DavMetaData>)
            } else {
                println!("File '{}' not found in cache", normalized_path);
                Err(dav_server::fs::FsError::NotFound)
            }
        })
    }

    fn create_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let path_str = path.as_url_string();
            println!("WebDAV create_dir for path: '{}'", path_str);

            // Normalize path
            let normalized_path = if path_str == "/" || path_str.is_empty() {
                return Err(dav_server::fs::FsError::Forbidden); // Can't create root
            } else {
                path_str.trim_start_matches('/')
            };

            // Check if directory already exists
            let cache = self.file_cache.read().await;
            if cache.contains_key(normalized_path) {
                return Err(dav_server::fs::FsError::Exists);
            }
            drop(cache);

            // Create directory on disk
            let disk_path = self.vault_path.join("files").join(normalized_path);
            std::fs::create_dir_all(&disk_path)
                .map_err(|e| {
                    eprintln!("Failed to create directory on disk: {}", e);
                    dav_server::fs::FsError::GeneralFailure
                })?;

            // Add to cache
            let mut cache = self.file_cache.write().await;
            cache.insert(normalized_path.to_string(), DecryptedFile {
                name: std::path::Path::new(normalized_path)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                content: Bytes::new(),
                size: 0,
                modified: std::time::SystemTime::now(),
                is_dir: true,
            });

            println!("Created directory: {}", normalized_path);
            Ok(())
        })
    }

    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let path_str = path.as_url_string();
            println!("WebDAV remove_file for path: '{}'", path_str);

            // Normalize path
            let normalized_path = if path_str == "/" || path_str.is_empty() {
                return Err(dav_server::fs::FsError::Forbidden); // Can't remove root
            } else {
                path_str.trim_start_matches('/')
            };

            // Check if file exists
            let cache = self.file_cache.read().await;
            let exists = cache.contains_key(normalized_path);
            drop(cache);

            if !exists {
                return Err(dav_server::fs::FsError::NotFound);
            }

            // Remove from disk
            let disk_path = self.vault_path.join("files").join(normalized_path);
            if disk_path.exists() {
                if disk_path.is_dir() {
                    std::fs::remove_dir_all(&disk_path)
                } else {
                    std::fs::remove_file(&disk_path)
                }.map_err(|e| {
                    eprintln!("Failed to remove file from disk: {}", e);
                    dav_server::fs::FsError::GeneralFailure
                })?;
            }

            // Remove from cache
            let mut cache = self.file_cache.write().await;
            cache.remove(normalized_path);

            println!("Removed file: {}", normalized_path);
            Ok(())
        })
    }

    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        // Use the same implementation as remove_file since we handle both cases
        self.remove_file(path)
    }

    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let from_str = from.as_url_string();
            let to_str = to.as_url_string();
            println!("WebDAV rename from '{}' to '{}'", from_str, to_str);

            // Normalize paths
            let from_normalized = from_str.trim_start_matches('/');
            let to_normalized = to_str.trim_start_matches('/');

            if from_normalized.is_empty() || to_normalized.is_empty() {
                return Err(dav_server::fs::FsError::Forbidden);
            }

            // Check if source exists
            let mut cache = self.file_cache.write().await;
            let file = cache.remove(from_normalized)
                .ok_or(dav_server::fs::FsError::NotFound)?;

            // Move on disk
            let from_disk = self.vault_path.join("files").join(from_normalized);
            let to_disk = self.vault_path.join("files").join(to_normalized);

            if from_disk.exists() {
                // Ensure parent directory exists
                if let Some(parent) = to_disk.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|_| dav_server::fs::FsError::GeneralFailure)?;
                }

                std::fs::rename(&from_disk, &to_disk)
                    .map_err(|e| {
                        eprintln!("Failed to rename file on disk: {}", e);
                        dav_server::fs::FsError::GeneralFailure
                    })?;
            }

            // Update cache with new path
            let mut updated_file = file;
            updated_file.name = std::path::Path::new(to_normalized)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            cache.insert(to_normalized.to_string(), updated_file);

            println!("Renamed '{}' to '{}'", from_normalized, to_normalized);
            Ok(())
        })
    }

    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let from_str = from.as_url_string();
            let to_str = to.as_url_string();
            println!("WebDAV copy from '{}' to '{}'", from_str, to_str);

            // Normalize paths
            let from_normalized = from_str.trim_start_matches('/');
            let to_normalized = to_str.trim_start_matches('/');

            if from_normalized.is_empty() || to_normalized.is_empty() {
                return Err(dav_server::fs::FsError::Forbidden);
            }

            // Get source file
            let cache = self.file_cache.read().await;
            let source_file = cache.get(from_normalized)
                .ok_or(dav_server::fs::FsError::NotFound)?
                .clone();
            drop(cache);

            // Copy on disk
            let from_disk = self.vault_path.join("files").join(from_normalized);
            let to_disk = self.vault_path.join("files").join(to_normalized);

            if from_disk.exists() {
                // Ensure parent directory exists
                if let Some(parent) = to_disk.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|_| dav_server::fs::FsError::GeneralFailure)?;
                }

                std::fs::copy(&from_disk, &to_disk)
                    .map_err(|e| {
                        eprintln!("Failed to copy file on disk: {}", e);
                        dav_server::fs::FsError::GeneralFailure
                    })?;
            }

            // Add to cache
            let mut cache = self.file_cache.write().await;
            let mut copied_file = source_file;
            copied_file.name = std::path::Path::new(to_normalized)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            cache.insert(to_normalized.to_string(), copied_file);

            println!("Copied '{}' to '{}'", from_normalized, to_normalized);
            Ok(())
        })
    }
}
