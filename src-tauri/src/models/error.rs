use serde::{Deserialize, Serialize};
use std::fmt;

/// Comprehensive error types for the secure file sharing application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AppError {
    /// Cryptographic operation failed
    CryptoError(CryptoError),
    /// File operation failed
    FileError(FileError),
    /// Group operation failed
    GroupError(GroupError),
    /// User operation failed
    UserError(UserError),
    /// Network operation failed
    NetworkError(NetworkError),
    /// Validation failed
    ValidationError(String),
    /// Internal application error
    InternalError(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::CryptoError(e) => write!(f, "Crypto error: {}", e),
            AppError::FileError(e) => write!(f, "File error: {}", e),
            AppError::GroupError(e) => write!(f, "Group error: {}", e),
            AppError::UserError(e) => write!(f, "User error: {}", e),
            AppError::NetworkError(e) => write!(f, "Network error: {}", e),
            AppError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            AppError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

/// Cryptographic errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptoError {
    /// Key generation failed
    KeyGenerationFailed,
    /// Key exchange failed
    KeyExchangeFailed,
    /// Encryption failed
    EncryptionFailed,
    /// Decryption failed
    DecryptionFailed,
    /// Signature verification failed
    SignatureVerificationFailed,
    /// Invalid key format
    InvalidKeyFormat,
    /// Missing cryptographic key
    MissingKey,
    /// Sender key operation failed
    SenderKeyError(String),
    /// PQXDH operation failed
    PQXDHError(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::KeyGenerationFailed => write!(f, "Key generation failed"),
            CryptoError::KeyExchangeFailed => write!(f, "Key exchange failed"),
            CryptoError::EncryptionFailed => write!(f, "Encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "Decryption failed"),
            CryptoError::SignatureVerificationFailed => write!(f, "Signature verification failed"),
            CryptoError::InvalidKeyFormat => write!(f, "Invalid key format"),
            CryptoError::MissingKey => write!(f, "Missing cryptographic key"),
            CryptoError::SenderKeyError(msg) => write!(f, "Sender key error: {}", msg),
            CryptoError::PQXDHError(msg) => write!(f, "PQXDH error: {}", msg),
        }
    }
}

/// File operation errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileError {
    /// File not found
    NotFound,
    /// File access denied
    AccessDenied,
    /// File is too large
    FileTooLarge,
    /// Invalid file format
    InvalidFormat,
    /// File is corrupted
    Corrupted,
    /// File already exists
    AlreadyExists,
    /// Disk space insufficient
    InsufficientSpace,
    /// File is locked by another process
    FileLocked,
    /// Checksum verification failed
    ChecksumMismatch,
    /// File operation timeout
    Timeout,
    /// IO error with description
    IoError(String),
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileError::NotFound => write!(f, "File not found"),
            FileError::AccessDenied => write!(f, "File access denied"),
            FileError::FileTooLarge => write!(f, "File is too large"),
            FileError::InvalidFormat => write!(f, "Invalid file format"),
            FileError::Corrupted => write!(f, "File is corrupted"),
            FileError::AlreadyExists => write!(f, "File already exists"),
            FileError::InsufficientSpace => write!(f, "Insufficient disk space"),
            FileError::FileLocked => write!(f, "File is locked by another process"),
            FileError::ChecksumMismatch => write!(f, "File checksum verification failed"),
            FileError::Timeout => write!(f, "File operation timeout"),
            FileError::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

/// Group operation errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GroupError {
    /// Group not found
    NotFound,
    /// User is not a member of the group
    NotMember,
    /// User is already a member of the group
    AlreadyMember,
    /// Insufficient permissions for the operation
    InsufficientPermissions,
    /// Group is at maximum capacity
    GroupFull,
    /// Cannot remove group creator
    CannotRemoveCreator,
    /// Group has been deleted
    GroupDeleted,
    /// Sender key not found for user
    SenderKeyNotFound,
    /// Invalid group settings
    InvalidSettings,
}

impl fmt::Display for GroupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GroupError::NotFound => write!(f, "Group not found"),
            GroupError::NotMember => write!(f, "User is not a member of the group"),
            GroupError::AlreadyMember => write!(f, "User is already a member of the group"),
            GroupError::InsufficientPermissions => write!(f, "Insufficient permissions"),
            GroupError::GroupFull => write!(f, "Group is at maximum capacity"),
            GroupError::CannotRemoveCreator => write!(f, "Cannot remove group creator"),
            GroupError::GroupDeleted => write!(f, "Group has been deleted"),
            GroupError::SenderKeyNotFound => write!(f, "Sender key not found for user"),
            GroupError::InvalidSettings => write!(f, "Invalid group settings"),
        }
    }
}

/// User operation errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserError {
    /// User not found
    NotFound,
    /// User is not authenticated
    NotAuthenticated,
    /// User account is suspended
    AccountSuspended,
    /// User account is deleted
    AccountDeleted,
    /// Invalid user credentials
    InvalidCredentials,
    /// User already exists
    AlreadyExists,
    /// Incomplete key bundle
    IncompleteKeyBundle,
    /// Invalid user status transition
    InvalidStatusTransition,
}

impl fmt::Display for UserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserError::NotFound => write!(f, "User not found"),
            UserError::NotAuthenticated => write!(f, "User is not authenticated"),
            UserError::AccountSuspended => write!(f, "User account is suspended"),
            UserError::AccountDeleted => write!(f, "User account is deleted"),
            UserError::InvalidCredentials => write!(f, "Invalid user credentials"),
            UserError::AlreadyExists => write!(f, "User already exists"),
            UserError::IncompleteKeyBundle => write!(f, "User has incomplete key bundle"),
            UserError::InvalidStatusTransition => write!(f, "Invalid user status transition"),
        }
    }
}

/// Network operation errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkError {
    /// Connection failed
    ConnectionFailed,
    /// Request timeout
    Timeout,
    /// Server error
    ServerError(u16),
    /// Network unreachable
    NetworkUnreachable,
    /// Invalid response format
    InvalidResponse,
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Authentication failed
    AuthenticationFailed,
    /// Service unavailable
    ServiceUnavailable,
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkError::ConnectionFailed => write!(f, "Connection failed"),
            NetworkError::Timeout => write!(f, "Request timeout"),
            NetworkError::ServerError(code) => write!(f, "Server error: {}", code),
            NetworkError::NetworkUnreachable => write!(f, "Network unreachable"),
            NetworkError::InvalidResponse => write!(f, "Invalid response format"),
            NetworkError::RateLimitExceeded => write!(f, "Rate limit exceeded"),
            NetworkError::AuthenticationFailed => write!(f, "Authentication failed"),
            NetworkError::ServiceUnavailable => write!(f, "Service unavailable"),
        }
    }
}

/// Result type for application operations
pub type AppResult<T> = Result<T, AppError>;

/// Convenience macros for creating errors
#[macro_export]
macro_rules! crypto_error {
    ($variant:ident) => {
        AppError::CryptoError(CryptoError::$variant)
    };
    ($variant:ident, $msg:expr) => {
        AppError::CryptoError(CryptoError::$variant($msg.to_string()))
    };
}

#[macro_export]
macro_rules! file_error {
    ($variant:ident) => {
        AppError::FileError(FileError::$variant)
    };
    ($variant:ident, $msg:expr) => {
        AppError::FileError(FileError::$variant($msg.to_string()))
    };
}

#[macro_export]
macro_rules! group_error {
    ($variant:ident) => {
        AppError::GroupError(GroupError::$variant)
    };
}

#[macro_export]
macro_rules! user_error {
    ($variant:ident) => {
        AppError::UserError(UserError::$variant)
    };
}

#[macro_export]
macro_rules! network_error {
    ($variant:ident) => {
        AppError::NetworkError(NetworkError::$variant)
    };
    ($variant:ident, $code:expr) => {
        AppError::NetworkError(NetworkError::$variant($code))
    };
}

#[macro_export]
macro_rules! validation_error {
    ($msg:expr) => {
        AppError::ValidationError($msg.to_string())
    };
}

#[macro_export]
macro_rules! internal_error {
    ($msg:expr) => {
        AppError::InternalError($msg.to_string())
    };
}
