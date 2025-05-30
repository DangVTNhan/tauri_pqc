use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Represents a user in the secure file sharing system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique identifier for the user
    pub id: Uuid,
    /// Display name of the user
    pub name: String,
    /// Registration ID for Signal protocol
    pub registration_id: u32,
    /// Device ID for this user's device
    pub device_id: u32,
    /// When the user was created
    pub created_at: DateTime<Utc>,
    /// User's current status
    pub status: UserStatus,

    // PQXDH key bundle for post-quantum key exchange
    /// Identity key pair for long-term identity
    pub identity_key_pair: Option<KeyPairData>,
    /// Signed pre-key for key exchange
    pub signed_pre_key: Option<SignedPreKeyData>,
    /// Kyber pre-key for post-quantum security
    pub kyber_pre_key: Option<KyberPreKeyData>,
    /// One-time pre-keys for forward secrecy
    pub one_time_pre_keys: Vec<PreKeyData>,

    /// Groups this user is a member of
    pub group_memberships: HashSet<Uuid>,
    /// User preferences and settings
    pub preferences: UserPreferences,
}

impl User {
    /// Create a new user with the given name
    pub fn new(name: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            registration_id: rand::random::<u32>() & 0x3FFF, // 14-bit registration ID
            device_id: 1, // Default device ID
            created_at: Utc::now(),
            status: UserStatus::Active,
            identity_key_pair: None,
            signed_pre_key: None,
            kyber_pre_key: None,
            one_time_pre_keys: Vec::new(),
            group_memberships: HashSet::new(),
            preferences: UserPreferences::default(),
        }
    }

    /// Check if the user has a complete PQXDH key bundle
    pub fn has_complete_key_bundle(&self) -> bool {
        self.identity_key_pair.is_some()
            && self.signed_pre_key.is_some()
            && self.kyber_pre_key.is_some()
            && !self.one_time_pre_keys.is_empty()
    }

    /// Add a group membership
    pub fn join_group(&mut self, group_id: Uuid) {
        self.group_memberships.insert(group_id);
    }

    /// Remove a group membership
    pub fn leave_group(&mut self, group_id: Uuid) {
        self.group_memberships.remove(&group_id);
    }

    /// Check if user is a member of a specific group
    pub fn is_member_of(&self, group_id: &Uuid) -> bool {
        self.group_memberships.contains(group_id)
    }

    /// Get the user's public key bundle for key exchange
    pub fn get_public_key_bundle(&self) -> Option<PublicKeyBundle> {
        if !self.has_complete_key_bundle() {
            return None;
        }

        Some(PublicKeyBundle {
            user_id: self.id,
            registration_id: self.registration_id,
            device_id: self.device_id,
            identity_key: self.identity_key_pair.as_ref()?.public_key.clone(),
            signed_pre_key: self.signed_pre_key.as_ref()?.clone(),
            kyber_pre_key: self.kyber_pre_key.as_ref()?.clone(),
            one_time_pre_key: self.one_time_pre_keys.first()?.clone(),
            timestamp: Utc::now(),
        })
    }

    /// Update user status
    pub fn set_status(&mut self, status: UserStatus) {
        self.status = status;
    }

    /// Check if user is active
    pub fn is_active(&self) -> bool {
        matches!(self.status, UserStatus::Active)
    }
}

/// Status of a user account
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UserStatus {
    /// User is active and can participate in groups
    Active,
    /// User is temporarily inactive
    Inactive,
    /// User account is suspended
    Suspended,
    /// User account is deleted
    Deleted,
}

/// User preferences and settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPreferences {
    /// Whether to auto-download files
    pub auto_download_files: bool,
    /// Maximum file size to auto-download (in bytes)
    pub max_auto_download_size: u64,
    /// Whether to show download notifications
    pub show_download_notifications: bool,
    /// Default download directory
    pub download_directory: Option<String>,
    /// Whether to verify file integrity automatically
    pub auto_verify_files: bool,
}

impl Default for UserPreferences {
    fn default() -> Self {
        Self {
            auto_download_files: false,
            max_auto_download_size: 10 * 1024 * 1024, // 10 MB
            show_download_notifications: true,
            download_directory: None,
            auto_verify_files: true,
        }
    }
}

/// Key pair data structure for cryptographic keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPairData {
    /// Public key bytes
    pub public_key: Vec<u8>,
    /// Private key bytes
    pub private_key: Vec<u8>,
    /// When this key pair was generated
    pub timestamp: DateTime<Utc>,
    /// Key algorithm used
    pub algorithm: String,
}

impl KeyPairData {
    /// Create a new key pair
    pub fn new(public_key: Vec<u8>, private_key: Vec<u8>, algorithm: String) -> Self {
        Self {
            public_key,
            private_key,
            timestamp: Utc::now(),
            algorithm,
        }
    }
}

/// Signed pre-key data for PQXDH
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPreKeyData {
    /// Pre-key ID
    pub id: u32,
    /// Public key bytes
    pub public_key: Vec<u8>,
    /// Private key bytes
    pub private_key: Vec<u8>,
    /// Signature over the public key
    pub signature: Vec<u8>,
    /// When this pre-key was generated
    pub timestamp: DateTime<Utc>,
    /// Key algorithm used
    pub algorithm: String,
}

impl SignedPreKeyData {
    /// Create a new signed pre-key
    pub fn new(
        id: u32,
        public_key: Vec<u8>,
        private_key: Vec<u8>,
        signature: Vec<u8>,
        algorithm: String,
    ) -> Self {
        Self {
            id,
            public_key,
            private_key,
            signature,
            timestamp: Utc::now(),
            algorithm,
        }
    }
}

/// Kyber pre-key data for post-quantum security
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyberPreKeyData {
    /// Pre-key ID
    pub id: u32,
    /// Kyber public key bytes
    pub public_key: Vec<u8>,
    /// Kyber private key bytes
    pub private_key: Vec<u8>,
    /// When this pre-key was generated
    pub timestamp: DateTime<Utc>,
    /// Kyber parameter set used
    pub parameter_set: String,
}

impl KyberPreKeyData {
    /// Create a new Kyber pre-key
    pub fn new(
        id: u32,
        public_key: Vec<u8>,
        private_key: Vec<u8>,
        parameter_set: String,
    ) -> Self {
        Self {
            id,
            public_key,
            private_key,
            timestamp: Utc::now(),
            parameter_set,
        }
    }
}

/// One-time pre-key data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyData {
    /// Pre-key ID
    pub id: u32,
    /// Public key bytes
    pub public_key: Vec<u8>,
    /// Private key bytes
    pub private_key: Vec<u8>,
    /// When this pre-key was generated
    pub timestamp: DateTime<Utc>,
    /// Key algorithm used
    pub algorithm: String,
}

impl PreKeyData {
    /// Create a new one-time pre-key
    pub fn new(
        id: u32,
        public_key: Vec<u8>,
        private_key: Vec<u8>,
        algorithm: String,
    ) -> Self {
        Self {
            id,
            public_key,
            private_key,
            timestamp: Utc::now(),
            algorithm,
        }
    }
}

/// Public key bundle for key exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyBundle {
    /// User ID this bundle belongs to
    pub user_id: Uuid,
    /// Registration ID
    pub registration_id: u32,
    /// Device ID
    pub device_id: u32,
    /// Identity public key
    pub identity_key: Vec<u8>,
    /// Signed pre-key
    pub signed_pre_key: SignedPreKeyData,
    /// Kyber pre-key
    pub kyber_pre_key: KyberPreKeyData,
    /// One-time pre-key
    pub one_time_pre_key: PreKeyData,
    /// When this bundle was created
    pub timestamp: DateTime<Utc>,
}

impl PublicKeyBundle {
    /// Validate the public key bundle
    pub fn validate(&self) -> Result<(), String> {
        if self.identity_key.is_empty() {
            return Err("Identity key cannot be empty".to_string());
        }

        if self.signed_pre_key.public_key.is_empty() {
            return Err("Signed pre-key cannot be empty".to_string());
        }

        if self.signed_pre_key.signature.is_empty() {
            return Err("Signed pre-key signature cannot be empty".to_string());
        }

        if self.kyber_pre_key.public_key.is_empty() {
            return Err("Kyber pre-key cannot be empty".to_string());
        }

        if self.one_time_pre_key.public_key.is_empty() {
            return Err("One-time pre-key cannot be empty".to_string());
        }

        Ok(())
    }
}
