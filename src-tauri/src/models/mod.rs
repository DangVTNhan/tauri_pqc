pub mod user;
pub mod group;
pub mod file;
pub mod error;
pub mod demo;

// Re-export user types
pub use user::{
    User, UserStatus, UserPreferences, KeyPairData, SignedPreKeyData,
    KyberPreKeyData, PreKeyData, PublicKeyBundle
};

// Re-export group types
pub use group::{
    Group, SenderKeyData, SenderKeyDistributionMessage, GroupSettings,
    GroupMember, GroupRole
};

// Re-export file types
pub use file::{
    SharedFile, FileEncryptionMetadata, FileStatus, KeyDerivationParams,
    FileShareProgress, FileOperation, FileDownloadRequest, DownloadPriority,
    format_file_size, get_mime_type
};

// Re-export error types
pub use error::{
    AppError, CryptoError, FileError, GroupError, UserError, NetworkError, AppResult
};