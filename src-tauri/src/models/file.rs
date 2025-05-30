use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Represents a file shared within a group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedFile {
    /// Unique identifier for this shared file
    pub id: Uuid,
    /// Original filename before encryption
    pub original_name: String,
    /// Encrypted filename for storage
    pub encrypted_name: String,
    /// File size in bytes
    pub size: i64,
    /// MIME type of the file
    pub mime_type: String,
    /// User ID who shared this file
    pub shared_by: Uuid,
    /// Timestamp when the file was shared
    pub shared_at: DateTime<Utc>,
    /// Encryption metadata for this file
    pub encryption_metadata: FileEncryptionMetadata,
    /// Set of user IDs who have downloaded this file
    pub downloaded_by: HashSet<Uuid>,
    /// Current status of the file
    pub status: FileStatus,
    /// Optional description or caption
    pub description: Option<String>,
    /// File path on the storage system
    pub storage_path: Option<String>,
}

impl SharedFile {
    /// Create a new shared file
    pub fn new(
        original_name: String,
        size: i64,
        mime_type: String,
        shared_by: Uuid,
        encryption_metadata: FileEncryptionMetadata,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            encrypted_name: format!("encrypted_{}", Uuid::new_v4()),
            original_name,
            size,
            mime_type,
            shared_by,
            shared_at: Utc::now(),
            encryption_metadata,
            downloaded_by: HashSet::new(),
            status: FileStatus::Available,
            description: None,
            storage_path: None,
        }
    }

    /// Mark file as downloaded by a user
    pub fn mark_downloaded_by(&mut self, user_id: Uuid) {
        self.downloaded_by.insert(user_id);
    }

    /// Check if a user has downloaded this file
    pub fn is_downloaded_by(&self, user_id: &Uuid) -> bool {
        self.downloaded_by.contains(user_id)
    }

    /// Get the number of users who have downloaded this file
    pub fn download_count(&self) -> usize {
        self.downloaded_by.len()
    }

    /// Check if the file is available for download
    pub fn is_available(&self) -> bool {
        matches!(self.status, FileStatus::Available)
    }

    /// Set file description
    pub fn set_description(&mut self, description: String) {
        self.description = Some(description);
    }

    /// Update file status
    pub fn set_status(&mut self, status: FileStatus) {
        self.status = status;
    }

    /// Get file extension from original name
    pub fn get_extension(&self) -> Option<&str> {
        self.original_name.split('.').last()
    }

    /// Check if this is an image file
    pub fn is_image(&self) -> bool {
        self.mime_type.starts_with("image/")
    }

    /// Check if this is a video file
    pub fn is_video(&self) -> bool {
        self.mime_type.starts_with("video/")
    }

    /// Check if this is an audio file
    pub fn is_audio(&self) -> bool {
        self.mime_type.starts_with("audio/")
    }

    /// Get human-readable file size
    pub fn get_formatted_size(&self) -> String {
        format_file_size(self.size as u64)
    }
}

/// Status of a shared file
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FileStatus {
    /// File is available for download
    Available,
    /// File is being uploaded
    Uploading,
    /// File upload failed
    UploadFailed,
    /// File has been deleted
    Deleted,
    /// File has expired based on group settings
    Expired,
    /// File is corrupted or verification failed
    Corrupted,
}

/// Metadata for file encryption using AES-256-GCM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEncryptionMetadata {
    /// Encryption key (32 bytes for AES-256)
    pub encryption_key: Vec<u8>,
    /// Initialization vector
    pub iv: Vec<u8>,
    /// Authentication tag for integrity verification
    pub auth_tag: Vec<u8>,
    /// Size of each encryption chunk in bytes
    pub chunk_size: u32,
    /// Total number of chunks
    pub total_chunks: u32,
    /// Encryption algorithm used
    pub algorithm: String,
    /// Key derivation parameters
    pub key_derivation: KeyDerivationParams,
    /// Checksum of the original file for integrity
    pub original_checksum: Vec<u8>,
    /// Checksum algorithm used
    pub checksum_algorithm: String,
}

impl FileEncryptionMetadata {
    /// Create new encryption metadata
    pub fn new(
        encryption_key: Vec<u8>,
        iv: Vec<u8>,
        auth_tag: Vec<u8>,
        chunk_size: u32,
        total_chunks: u32,
        original_checksum: Vec<u8>,
    ) -> Self {
        Self {
            encryption_key,
            iv,
            auth_tag,
            chunk_size,
            total_chunks,
            algorithm: "AES-256-GCM".to_string(),
            key_derivation: KeyDerivationParams::default(),
            original_checksum,
            checksum_algorithm: "SHA-256".to_string(),
        }
    }

    /// Validate the encryption metadata
    pub fn validate(&self) -> Result<(), String> {
        if self.encryption_key.len() != 32 {
            return Err("Invalid encryption key length".to_string());
        }

        if self.iv.is_empty() {
            return Err("IV cannot be empty".to_string());
        }

        if self.auth_tag.is_empty() {
            return Err("Auth tag cannot be empty".to_string());
        }

        if self.chunk_size == 0 {
            return Err("Chunk size must be greater than 0".to_string());
        }

        if self.total_chunks == 0 {
            return Err("Total chunks must be greater than 0".to_string());
        }

        Ok(())
    }

    /// Calculate estimated encrypted file size
    pub fn estimated_encrypted_size(&self) -> u64 {
        // Each chunk adds overhead for nonce and auth tag
        let overhead_per_chunk = 12 + 16; // 12 bytes nonce + 16 bytes tag
        let total_overhead = self.total_chunks as u64 * overhead_per_chunk;
        let original_size = self.chunk_size as u64 * self.total_chunks as u64;
        original_size + total_overhead
    }
}

/// Parameters for key derivation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationParams {
    /// Salt used for key derivation
    pub salt: Vec<u8>,
    /// Number of iterations for PBKDF2
    pub iterations: u32,
    /// Key derivation function used
    pub kdf: String,
    /// Additional info for HKDF
    pub info: Option<Vec<u8>>,
}

impl Default for KeyDerivationParams {
    fn default() -> Self {
        Self {
            salt: Vec::new(),
            iterations: 100_000,
            kdf: "HKDF-SHA256".to_string(),
            info: None,
        }
    }
}

/// File sharing progress information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileShareProgress {
    /// File ID being processed
    pub file_id: Uuid,
    /// Current progress (0.0 to 1.0)
    pub progress: f64,
    /// Current operation being performed
    pub operation: FileOperation,
    /// Bytes processed so far
    pub bytes_processed: u64,
    /// Total bytes to process
    pub total_bytes: u64,
    /// Estimated time remaining in seconds
    pub eta_seconds: Option<u32>,
    /// Current transfer speed in bytes per second
    pub speed_bps: Option<u64>,
}

/// Operations that can be performed on files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileOperation {
    /// Reading file from disk
    Reading,
    /// Encrypting file data
    Encrypting,
    /// Uploading encrypted file
    Uploading,
    /// Downloading encrypted file
    Downloading,
    /// Decrypting file data
    Decrypting,
    /// Writing file to disk
    Writing,
    /// Verifying file integrity
    Verifying,
}

/// File download request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDownloadRequest {
    /// File ID to download
    pub file_id: Uuid,
    /// User requesting the download
    pub requested_by: Uuid,
    /// Group ID where the file is shared
    pub group_id: Uuid,
    /// Timestamp of the request
    pub requested_at: DateTime<Utc>,
    /// Priority of the download
    pub priority: DownloadPriority,
}

/// Priority levels for file downloads
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum DownloadPriority {
    Low,
    Normal,
    High,
    Urgent,
}

/// Utility function to format file size in human-readable format
pub fn format_file_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = size as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", size as u64, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

/// Utility function to get MIME type from file extension
pub fn get_mime_type(extension: &str) -> String {
    match extension.to_lowercase().as_str() {
        "txt" => "text/plain".to_string(),
        "pdf" => "application/pdf".to_string(),
        "doc" | "docx" => "application/msword".to_string(),
        "jpg" | "jpeg" => "image/jpeg".to_string(),
        "png" => "image/png".to_string(),
        "gif" => "image/gif".to_string(),
        "mp4" => "video/mp4".to_string(),
        "mp3" => "audio/mpeg".to_string(),
        "zip" => "application/zip".to_string(),
        "json" => "application/json".to_string(),
        "xml" => "application/xml".to_string(),
        _ => "application/octet-stream".to_string(),
    }
}