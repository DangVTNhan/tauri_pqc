use async_trait::async_trait;
use uuid::Uuid;
use std::collections::HashMap;

use crate::models::{
    User, Group, SharedFile, SenderKeyData, GroupMember, FileStatus,
    KeyPairData, SignedPreKeyData, KyberPreKeyData, PreKeyData, PublicKeyBundle
};
use super::error::StorageResult;

/// Transaction trait for atomic operations
#[async_trait]
pub trait Transaction: Send + Sync {
    /// Commit the transaction
    async fn commit(&mut self) -> StorageResult<()>;

    /// Rollback the transaction
    async fn rollback(&mut self) -> StorageResult<()>;
}

/// Main storage trait defining all storage operations
#[async_trait]
pub trait Storage: Send + Sync {
    type Transaction: Transaction;

    /// Initialize the storage backend
    async fn initialize(&mut self) -> StorageResult<()>;

    /// Check if storage is healthy and accessible
    async fn health_check(&self) -> StorageResult<()>;

    /// Begin a new transaction
    async fn begin_transaction(&self) -> StorageResult<Box<Self::Transaction>>;

    // User operations
    /// Create a new user
    async fn create_user(&self, user: &User) -> StorageResult<()>;

    /// Get user by ID
    async fn get_user(&self, user_id: &Uuid) -> StorageResult<User>;

    /// Update an existing user
    async fn update_user(&self, user: &User) -> StorageResult<()>;

    /// Delete a user
    async fn delete_user(&self, user_id: &Uuid) -> StorageResult<()>;

    /// List all users
    async fn list_users(&self) -> StorageResult<Vec<User>>;

    /// Find users by name pattern
    async fn find_users_by_name(&self, pattern: &str) -> StorageResult<Vec<User>>;

    /// Get users by IDs
    async fn get_users(&self, user_ids: &[Uuid]) -> StorageResult<Vec<User>>;

    // Group operations
    /// Create a new group
    async fn create_group(&self, group: &Group) -> StorageResult<()>;

    /// Get group by ID
    async fn get_group(&self, group_id: &Uuid) -> StorageResult<Group>;

    /// Update an existing group
    async fn update_group(&self, group: &Group) -> StorageResult<()>;

    /// Delete a group
    async fn delete_group(&self, group_id: &Uuid) -> StorageResult<()>;

    /// List all groups
    async fn list_groups(&self) -> StorageResult<Vec<Group>>;

    /// Get groups for a user
    async fn get_user_groups(&self, user_id: &Uuid) -> StorageResult<Vec<Group>>;

    /// Add member to group
    async fn add_group_member(&self, group_id: &Uuid, user_id: &Uuid) -> StorageResult<()>;

    /// Remove member from group
    async fn remove_group_member(&self, group_id: &Uuid, user_id: &Uuid) -> StorageResult<()>;

    // File operations
    /// Create a new shared file
    async fn create_shared_file(&self, file: &SharedFile) -> StorageResult<()>;

    /// Get shared file by ID
    async fn get_shared_file(&self, file_id: &Uuid) -> StorageResult<SharedFile>;

    /// Update an existing shared file
    async fn update_shared_file(&self, file: &SharedFile) -> StorageResult<()>;

    /// Delete a shared file
    async fn delete_shared_file(&self, file_id: &Uuid) -> StorageResult<()>;

    /// List all shared files
    async fn list_shared_files(&self) -> StorageResult<Vec<SharedFile>>;

    /// Get files shared in a group
    async fn get_group_files(&self, group_id: &Uuid) -> StorageResult<Vec<SharedFile>>;

    /// Get files shared by a user
    async fn get_user_files(&self, user_id: &Uuid) -> StorageResult<Vec<SharedFile>>;

    /// Mark file as downloaded by user
    async fn mark_file_downloaded(&self, file_id: &Uuid, user_id: &Uuid) -> StorageResult<()>;

    /// Update file status
    async fn update_file_status(&self, file_id: &Uuid, status: FileStatus) -> StorageResult<()>;

    // Sender key operations
    /// Store sender key for a user in a group
    async fn store_sender_key(
        &self,
        group_id: &Uuid,
        user_id: &Uuid,
        sender_key: &SenderKeyData,
    ) -> StorageResult<()>;

    /// Get sender key for a user in a group
    async fn get_sender_key(
        &self,
        group_id: &Uuid,
        user_id: &Uuid,
    ) -> StorageResult<SenderKeyData>;

    /// Update sender key
    async fn update_sender_key(
        &self,
        group_id: &Uuid,
        user_id: &Uuid,
        sender_key: &SenderKeyData,
    ) -> StorageResult<()>;

    /// Delete sender key
    async fn delete_sender_key(&self, group_id: &Uuid, user_id: &Uuid) -> StorageResult<()>;

    /// Get all sender keys for a group
    async fn get_group_sender_keys(&self, group_id: &Uuid) -> StorageResult<HashMap<Uuid, SenderKeyData>>;

    // Key bundle operations
    /// Store user's key bundle
    async fn store_key_bundle(&self, user_id: &Uuid, bundle: &PublicKeyBundle) -> StorageResult<()>;

    /// Get user's public key bundle
    async fn get_key_bundle(&self, user_id: &Uuid) -> StorageResult<PublicKeyBundle>;

    /// Update user's key bundle
    async fn update_key_bundle(&self, user_id: &Uuid, bundle: &PublicKeyBundle) -> StorageResult<()>;

    /// Delete user's key bundle
    async fn delete_key_bundle(&self, user_id: &Uuid) -> StorageResult<()>;

    // Utility operations
    /// Get storage statistics
    async fn get_statistics(&self) -> StorageResult<StorageStatistics>;

    /// Cleanup expired data
    async fn cleanup_expired_data(&self) -> StorageResult<u64>;

    /// Backup data to a file
    async fn backup_to_file(&self, path: &str) -> StorageResult<()>;

    /// Restore data from a file
    async fn restore_from_file(&self, path: &str) -> StorageResult<()>;

    /// Vacuum/optimize storage
    async fn optimize(&self) -> StorageResult<()>;
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct StorageStatistics {
    /// Total number of users
    pub user_count: u64,
    /// Total number of groups
    pub group_count: u64,
    /// Total number of shared files
    pub file_count: u64,
    /// Total number of sender keys
    pub sender_key_count: u64,
    /// Total storage size in bytes
    pub total_size: u64,
    /// Number of encrypted records
    pub encrypted_records: u64,
    /// Last cleanup timestamp
    pub last_cleanup: Option<chrono::DateTime<chrono::Utc>>,
    /// Database version/schema version
    pub schema_version: u32,
}

impl Default for StorageStatistics {
    fn default() -> Self {
        Self {
            user_count: 0,
            group_count: 0,
            file_count: 0,
            sender_key_count: 0,
            total_size: 0,
            encrypted_records: 0,
            last_cleanup: None,
            schema_version: 1,
        }
    }
}

/// Query options for listing operations
#[derive(Debug, Clone, Default)]
pub struct QueryOptions {
    /// Maximum number of results to return
    pub limit: Option<u64>,
    /// Number of results to skip
    pub offset: Option<u64>,
    /// Sort field
    pub sort_by: Option<String>,
    /// Sort direction (true = ascending, false = descending)
    pub ascending: bool,
    /// Filter conditions
    pub filters: HashMap<String, String>,
}

impl QueryOptions {
    /// Create new query options
    pub fn new() -> Self {
        Self::default()
    }

    /// Set limit
    pub fn limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set offset
    pub fn offset(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Set sort field and direction
    pub fn sort(mut self, field: &str, ascending: bool) -> Self {
        self.sort_by = Some(field.to_string());
        self.ascending = ascending;
        self
    }

    /// Add filter condition
    pub fn filter(mut self, key: &str, value: &str) -> Self {
        self.filters.insert(key.to_string(), value.to_string());
        self
    }
}

/// Extended storage trait with query capabilities
#[async_trait]
pub trait QueryableStorage: Storage {
    /// List users with query options
    async fn query_users(&self, options: &QueryOptions) -> StorageResult<Vec<User>>;

    /// List groups with query options
    async fn query_groups(&self, options: &QueryOptions) -> StorageResult<Vec<Group>>;

    /// List files with query options
    async fn query_files(&self, options: &QueryOptions) -> StorageResult<Vec<SharedFile>>;

    /// Count users matching criteria
    async fn count_users(&self, filters: &HashMap<String, String>) -> StorageResult<u64>;

    /// Count groups matching criteria
    async fn count_groups(&self, filters: &HashMap<String, String>) -> StorageResult<u64>;

    /// Count files matching criteria
    async fn count_files(&self, filters: &HashMap<String, String>) -> StorageResult<u64>;
}
