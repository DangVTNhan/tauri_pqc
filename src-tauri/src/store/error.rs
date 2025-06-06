use thiserror::Error;
use uuid::Uuid;

/// Storage-specific error types
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("User not found: {id}")]
    UserNotFound { id: Uuid },

    #[error("Group not found: {id}")]
    GroupNotFound { id: Uuid },

    #[error("File not found: {id}")]
    FileNotFound { id: Uuid },

    #[error("Sender key not found for user {user_id} in group {group_id}")]
    SenderKeyNotFound { user_id: Uuid, group_id: Uuid },

    #[error("Invalid encryption key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Invalid initialization vector length: expected {expected}, got {actual}")]
    InvalidIvLength { expected: usize, actual: usize },

    #[error("Authentication tag verification failed")]
    AuthenticationFailed,

    #[error("Storage backend not initialized")]
    NotInitialized,

    #[error("Transaction error: {0}")]
    Transaction(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Migration error: {0}")]
    Migration(String),

    #[error("Concurrent access error: {0}")]
    ConcurrentAccess(String),

    #[error("Data integrity error: {0}")]
    DataIntegrity(String),

    #[error("Storage quota exceeded")]
    QuotaExceeded,

    #[error("Invalid storage path: {path}")]
    InvalidPath { path: String },

    #[error("Permission denied for operation: {operation}")]
    PermissionDenied { operation: String },
}

/// Result type for storage operations
pub type StorageResult<T> = Result<T, StorageError>;

impl StorageError {
    /// Create an encryption error
    pub fn encryption<S: Into<String>>(msg: S) -> Self {
        Self::Encryption(msg.into())
    }

    /// Create a decryption error
    pub fn decryption<S: Into<String>>(msg: S) -> Self {
        Self::Decryption(msg.into())
    }

    /// Create a key derivation error
    pub fn key_derivation<S: Into<String>>(msg: S) -> Self {
        Self::KeyDerivation(msg.into())
    }

    /// Create a serialization error
    pub fn serialization<S: Into<String>>(msg: S) -> Self {
        // Create a custom IO error and convert it to serde_json::Error
        let io_error = std::io::Error::new(std::io::ErrorKind::InvalidData, msg.into());
        Self::Serialization(serde_json::Error::io(io_error))
    }

    /// Create a transaction error
    pub fn transaction<S: Into<String>>(msg: S) -> Self {
        Self::Transaction(msg.into())
    }

    /// Create a configuration error
    pub fn configuration<S: Into<String>>(msg: S) -> Self {
        Self::Configuration(msg.into())
    }

    /// Create a migration error
    pub fn migration<S: Into<String>>(msg: S) -> Self {
        Self::Migration(msg.into())
    }

    /// Create a concurrent access error
    pub fn concurrent_access<S: Into<String>>(msg: S) -> Self {
        Self::ConcurrentAccess(msg.into())
    }

    /// Create a data integrity error
    pub fn data_integrity<S: Into<String>>(msg: S) -> Self {
        Self::DataIntegrity(msg.into())
    }

    /// Create a permission denied error
    pub fn permission_denied<S: Into<String>>(operation: S) -> Self {
        Self::PermissionDenied {
            operation: operation.into(),
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::Database(sqlx::Error::RowNotFound) => true,
            Self::UserNotFound { .. } => true,
            Self::GroupNotFound { .. } => true,
            Self::FileNotFound { .. } => true,
            Self::SenderKeyNotFound { .. } => true,
            Self::ConcurrentAccess(_) => true,
            _ => false,
        }
    }

    /// Check if this error indicates a missing resource
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::UserNotFound { .. }
                | Self::GroupNotFound { .. }
                | Self::FileNotFound { .. }
                | Self::SenderKeyNotFound { .. }
                | Self::Database(sqlx::Error::RowNotFound)
        )
    }

    /// Check if this error is related to cryptography
    pub fn is_crypto_error(&self) -> bool {
        matches!(
            self,
            Self::Encryption(_)
                | Self::Decryption(_)
                | Self::KeyDerivation(_)
                | Self::InvalidKeyLength { .. }
                | Self::InvalidIvLength { .. }
                | Self::AuthenticationFailed
        )
    }
}

// Integration with existing AppError from models/error.rs
impl From<StorageError> for crate::models::AppError {
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::Database(db_err) => {
                crate::models::AppError::InternalError(format!("Storage database error: {}", db_err))
            }
            StorageError::Encryption(msg) => {
                crate::models::AppError::CryptoError(crate::models::CryptoError::EncryptionFailed)
            }
            StorageError::Decryption(msg) => {
                crate::models::AppError::CryptoError(crate::models::CryptoError::DecryptionFailed)
            }
            StorageError::UserNotFound { id } => {
                crate::models::AppError::UserError(crate::models::UserError::NotFound)
            }
            StorageError::GroupNotFound { id } => {
                crate::models::AppError::GroupError(crate::models::GroupError::NotFound)
            }
            StorageError::FileNotFound { id } => {
                crate::models::AppError::FileError(crate::models::FileError::NotFound)
            }
            StorageError::Io(io_err) => {
                crate::models::AppError::FileError(crate::models::FileError::IoError(io_err.to_string()))
            }
            _ => crate::models::AppError::InternalError(err.to_string()),
        }
    }
}

impl From<sqlx::migrate::MigrateError> for StorageError {
    fn from(err: sqlx::migrate::MigrateError) -> Self {
        Self::Migration(err.to_string())
    }
}
