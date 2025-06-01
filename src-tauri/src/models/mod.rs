pub mod user;
pub mod group;
pub mod file;
pub mod error;
pub mod demo;
pub mod config;
pub mod vault;
pub mod webdav;

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

// Re-export config types
pub use config::{
    AppConfig, WindowConfig, VaultConfig, AppPreferences, ThemeMode
};

// Re-export vault types
pub use vault::{
    VaultMasterKey, VaultMetadata, CreateVaultRequest, CreateVaultResponse
};

// Re-export webdav types
pub use webdav::{
    WebDavConfig, VaultStatus, VaultMount, UnlockVaultRequest,
    UnlockVaultResponse, LockVaultResponse,
    WebDavState
};