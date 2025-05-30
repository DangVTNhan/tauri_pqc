use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use super::file::{SharedFile, FileEncryptionMetadata};

/// Represents a secure group for file sharing using Signal's Sender Key protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// Unique identifier for the group
    pub id: Uuid,
    /// Human-readable name of the group
    pub name: String,
    /// User ID of the group creator
    pub created_by: Uuid,
    /// Timestamp when the group was created
    pub created_at: DateTime<Utc>,
    /// Set of user IDs who are members of this group
    pub members: HashSet<Uuid>,
    /// Mapping of user ID to their sender key data for this group
    pub sender_keys: HashMap<Uuid, SenderKeyData>,
    /// List of files shared in this group
    pub shared_files: Vec<SharedFile>,
    /// Group settings and permissions
    pub settings: GroupSettings,
}

impl Group {
    /// Create a new group with the specified creator
    pub fn new(name: String, created_by: Uuid) -> Self {
        let mut members = HashSet::new();
        members.insert(created_by);

        Self {
            id: Uuid::new_v4(),
            name,
            created_by,
            created_at: Utc::now(),
            members,
            sender_keys: HashMap::new(),
            shared_files: Vec::new(),
            settings: GroupSettings::default(),
        }
    }

    /// Add a member to the group
    pub fn add_member(&mut self, user_id: Uuid) -> bool {
        self.members.insert(user_id)
    }

    /// Remove a member from the group
    pub fn remove_member(&mut self, user_id: Uuid) -> bool {
        // Don't allow removing the creator
        if user_id == self.created_by {
            return false;
        }

        // Remove member and their sender key
        self.sender_keys.remove(&user_id);
        self.members.remove(&user_id)
    }

    /// Check if a user is a member of this group
    pub fn is_member(&self, user_id: &Uuid) -> bool {
        self.members.contains(user_id)
    }

    /// Get sender key for a specific user
    pub fn get_sender_key(&self, user_id: &Uuid) -> Option<&SenderKeyData> {
        self.sender_keys.get(user_id)
    }

    /// Store sender key for a user
    pub fn store_sender_key(&mut self, user_id: Uuid, sender_key: SenderKeyData) {
        if self.is_member(&user_id) {
            self.sender_keys.insert(user_id, sender_key);
        }
    }

    /// Add a shared file to the group
    pub fn add_shared_file(&mut self, file: SharedFile) {
        self.shared_files.push(file);
    }

    /// Get all files shared by a specific user
    pub fn get_files_by_user(&self, user_id: &Uuid) -> Vec<&SharedFile> {
        self.shared_files
            .iter()
            .filter(|file| &file.shared_by == user_id)
            .collect()
    }
}

/// Signal Sender Key data for group messaging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKeyData {
    /// User ID this sender key belongs to
    pub user_id: Uuid,
    /// Distribution ID for this sender key
    pub distribution_id: Uuid,
    /// Chain ID for the sender key
    pub chain_id: u32,
    /// Current iteration number
    pub iteration: u32,
    /// Chain key for deriving message keys
    pub chain_key: Vec<u8>,
    /// Public signing key
    pub public_key: Vec<u8>,
    /// Private signing key (only for own keys)
    pub private_key: Option<Vec<u8>>,
    /// Timestamp when this key was created
    pub timestamp: DateTime<Utc>,
    /// Message version for protocol compatibility
    pub message_version: u8,
}

impl SenderKeyData {
    /// Create a new sender key for a user
    pub fn new(
        user_id: Uuid,
        distribution_id: Uuid,
        chain_id: u32,
        iteration: u32,
        chain_key: Vec<u8>,
        public_key: Vec<u8>,
        private_key: Option<Vec<u8>>,
    ) -> Self {
        Self {
            user_id,
            distribution_id,
            chain_id,
            iteration,
            chain_key,
            public_key,
            private_key,
            timestamp: Utc::now(),
            message_version: 3, // Current Signal protocol version
        }
    }

    /// Check if this is our own sender key (has private key)
    pub fn is_own_key(&self) -> bool {
        self.private_key.is_some()
    }

    /// Advance the chain key iteration
    pub fn advance_iteration(&mut self) {
        self.iteration += 1;
        // In a real implementation, this would derive the next chain key
        // For now, we'll leave the chain_key as-is
    }
}

/// Message for distributing sender keys to group members
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKeyDistributionMessage {
    /// Distribution ID for this sender key
    pub distribution_id: Uuid,
    /// Chain ID for the sender key
    pub chain_id: u32,
    /// Current iteration number
    pub iteration: u32,
    /// Chain key for deriving message keys
    pub chain_key: Vec<u8>,
    /// Public signing key
    pub signing_key: Vec<u8>,
    /// Timestamp when this message was created
    pub timestamp: DateTime<Utc>,
    /// Message version for protocol compatibility
    pub message_version: u8,
}

impl SenderKeyDistributionMessage {
    /// Create a new distribution message from sender key data
    pub fn from_sender_key(sender_key: &SenderKeyData) -> Self {
        Self {
            distribution_id: sender_key.distribution_id,
            chain_id: sender_key.chain_id,
            iteration: sender_key.iteration,
            chain_key: sender_key.chain_key.clone(),
            signing_key: sender_key.public_key.clone(),
            timestamp: Utc::now(),
            message_version: sender_key.message_version,
        }
    }
}

/// Group settings and permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSettings {
    /// Maximum file size allowed in bytes
    pub max_file_size: u64,
    /// Whether new members can see old files
    pub allow_historical_access: bool,
    /// Whether members can add new members
    pub allow_member_invites: bool,
    /// File retention period in days (0 = no limit)
    pub file_retention_days: u32,
}

impl Default for GroupSettings {
    fn default() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024, // 100 MB
            allow_historical_access: true,
            allow_member_invites: false,
            file_retention_days: 0, // No limit
        }
    }
}

/// Represents a group member with their role and status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    /// User ID
    pub user_id: Uuid,
    /// Member's role in the group
    pub role: GroupRole,
    /// When the user joined the group
    pub joined_at: DateTime<Utc>,
    /// Whether the member has a valid sender key
    pub has_sender_key: bool,
    /// Last time the member was active
    pub last_active: Option<DateTime<Utc>>,
}

/// Roles that group members can have
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GroupRole {
    /// Group creator with full permissions
    Admin,
    /// Regular member with standard permissions
    Member,
    /// Read-only member (can download but not share)
    ReadOnly,
}

impl GroupMember {
    /// Create a new group member
    pub fn new(user_id: Uuid, role: GroupRole) -> Self {
        Self {
            user_id,
            role,
            joined_at: Utc::now(),
            has_sender_key: false,
            last_active: None,
        }
    }

    /// Check if this member can share files
    pub fn can_share_files(&self) -> bool {
        matches!(self.role, GroupRole::Admin | GroupRole::Member)
    }

    /// Check if this member can add other members
    pub fn can_add_members(&self) -> bool {
        matches!(self.role, GroupRole::Admin)
    }

    /// Update the member's last active timestamp
    pub fn update_activity(&mut self) {
        self.last_active = Some(Utc::now());
    }
}