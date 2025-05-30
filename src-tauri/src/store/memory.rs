use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::models::{
    User, Group, SharedFile, SenderKeyData, GroupMember, FileStatus,
    KeyPairData, SignedPreKeyData, KyberPreKeyData, PreKeyData, PublicKeyBundle
};

use super::{
    traits::{Storage, Transaction, StorageStatistics, QueryOptions, QueryableStorage},
    error::{StorageError, StorageResult},
    config::MemoryConfig,
    encryption::EncryptionService,
};

/// In-memory storage data container
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
struct MemoryData {
    users: HashMap<Uuid, User>,
    groups: HashMap<Uuid, Group>,
    files: HashMap<Uuid, SharedFile>,
    sender_keys: HashMap<(Uuid, Uuid), SenderKeyData>, // (group_id, user_id) -> SenderKeyData
    key_bundles: HashMap<Uuid, PublicKeyBundle>,
}

/// In-memory transaction implementation
pub struct MemoryTransaction {
    storage: Arc<RwLock<MemoryData>>,
    snapshot: MemoryData,
    committed: bool,
}

#[async_trait]
impl Transaction for MemoryTransaction {
    async fn commit(&mut self) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::transaction("Transaction already committed"));
        }

        let mut storage = self.storage.write().await;
        *storage = self.snapshot.clone();
        self.committed = true;
        Ok(())
    }

    async fn rollback(&mut self) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::transaction("Transaction already committed"));
        }

        // Simply drop the snapshot, no changes to storage
        self.committed = true;
        Ok(())
    }
}

/// In-memory storage implementation for testing
pub struct MemoryStorage {
    data: Arc<RwLock<MemoryData>>,
    config: MemoryConfig,
    encryption: Option<EncryptionService>,
}

impl MemoryStorage {
    /// Create a new in-memory storage instance
    pub fn new(config: MemoryConfig) -> Self {
        Self {
            data: Arc::new(RwLock::new(MemoryData::default())),
            config,
            encryption: None,
        }
    }

    /// Create a new in-memory storage with encryption
    pub fn with_encryption(config: MemoryConfig, encryption: EncryptionService) -> Self {
        Self {
            data: Arc::new(RwLock::new(MemoryData::default())),
            config,
            encryption: Some(encryption),
        }
    }

    /// Check if storage has reached capacity
    async fn check_capacity(&self) -> StorageResult<()> {
        if let Some(max_items) = self.config.max_items {
            let data = self.data.read().await;
            let total_items = data.users.len() + data.groups.len() + data.files.len();

            if total_items >= max_items {
                return Err(StorageError::QuotaExceeded);
            }
        }
        Ok(())
    }

    /// Persist data to disk if configured
    async fn persist_if_enabled(&self) -> StorageResult<()> {
        if self.config.persist_to_disk {
            if let Some(path) = &self.config.persistence_path {
                let data = self.data.read().await;
                let json = serde_json::to_string_pretty(&*data)?;
                tokio::fs::write(path, json).await?;
            }
        }
        Ok(())
    }

    /// Load data from disk if configured
    async fn load_if_enabled(&mut self) -> StorageResult<()> {
        if self.config.persist_to_disk {
            if let Some(path) = &self.config.persistence_path {
                if path.exists() {
                    let json = tokio::fs::read_to_string(path).await?;
                    let loaded_data: MemoryData = serde_json::from_str(&json)?;
                    let mut data = self.data.write().await;
                    *data = loaded_data;
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    type Transaction = MemoryTransaction;

    async fn initialize(&mut self) -> StorageResult<()> {
        self.load_if_enabled().await?;
        Ok(())
    }

    async fn health_check(&self) -> StorageResult<()> {
        // Memory storage is always healthy if accessible
        let _data = self.data.read().await;
        Ok(())
    }

    async fn begin_transaction(&self) -> StorageResult<Box<Self::Transaction>> {
        let data = self.data.read().await;
        let snapshot = data.clone();

        Ok(Box::new(MemoryTransaction {
            storage: self.data.clone(),
            snapshot,
            committed: false,
        }))
    }

    // User operations
    async fn create_user(&self, user: &User) -> StorageResult<()> {
        self.check_capacity().await?;

        let mut data = self.data.write().await;
        if data.users.contains_key(&user.id) {
            return Err(StorageError::data_integrity(format!(
                "User with ID {} already exists",
                user.id
            )));
        }

        data.users.insert(user.id, user.clone());
        drop(data);
        self.persist_if_enabled().await?;
        Ok(())
    }

    async fn get_user(&self, user_id: &Uuid) -> StorageResult<User> {
        let data = self.data.read().await;
        data.users
            .get(user_id)
            .cloned()
            .ok_or(StorageError::UserNotFound { id: *user_id })
    }

    async fn update_user(&self, user: &User) -> StorageResult<()> {
        let mut data = self.data.write().await;
        if !data.users.contains_key(&user.id) {
            return Err(StorageError::UserNotFound { id: user.id });
        }

        data.users.insert(user.id, user.clone());
        drop(data);
        self.persist_if_enabled().await?;
        Ok(())
    }

    async fn delete_user(&self, user_id: &Uuid) -> StorageResult<()> {
        let mut data = self.data.write().await;
        if data.users.remove(user_id).is_none() {
            return Err(StorageError::UserNotFound { id: *user_id });
        }

        // Clean up related data
        data.key_bundles.remove(user_id);
        data.sender_keys.retain(|(_, uid), _| uid != user_id);

        drop(data);
        self.persist_if_enabled().await?;
        Ok(())
    }

    async fn list_users(&self) -> StorageResult<Vec<User>> {
        let data = self.data.read().await;
        Ok(data.users.values().cloned().collect())
    }

    async fn find_users_by_name(&self, pattern: &str) -> StorageResult<Vec<User>> {
        let data = self.data.read().await;
        let pattern = pattern.to_lowercase();
        Ok(data
            .users
            .values()
            .filter(|user| user.name.to_lowercase().contains(&pattern))
            .cloned()
            .collect())
    }

    async fn get_users(&self, user_ids: &[Uuid]) -> StorageResult<Vec<User>> {
        let data = self.data.read().await;
        let mut users = Vec::new();

        for user_id in user_ids {
            if let Some(user) = data.users.get(user_id) {
                users.push(user.clone());
            }
        }

        Ok(users)
    }

    // Group operations
    async fn create_group(&self, group: &Group) -> StorageResult<()> {
        self.check_capacity().await?;

        let mut data = self.data.write().await;
        if data.groups.contains_key(&group.id) {
            return Err(StorageError::data_integrity(format!(
                "Group with ID {} already exists",
                group.id
            )));
        }

        data.groups.insert(group.id, group.clone());
        drop(data);
        self.persist_if_enabled().await?;
        Ok(())
    }

    async fn get_group(&self, group_id: &Uuid) -> StorageResult<Group> {
        let data = self.data.read().await;
        data.groups
            .get(group_id)
            .cloned()
            .ok_or(StorageError::GroupNotFound { id: *group_id })
    }

    async fn update_group(&self, group: &Group) -> StorageResult<()> {
        let mut data = self.data.write().await;
        if !data.groups.contains_key(&group.id) {
            return Err(StorageError::GroupNotFound { id: group.id });
        }

        data.groups.insert(group.id, group.clone());
        drop(data);
        self.persist_if_enabled().await?;
        Ok(())
    }

    async fn delete_group(&self, group_id: &Uuid) -> StorageResult<()> {
        let mut data = self.data.write().await;
        if data.groups.remove(group_id).is_none() {
            return Err(StorageError::GroupNotFound { id: *group_id });
        }

        // Clean up related data
        data.sender_keys.retain(|(gid, _), _| gid != group_id);
        // Note: Files are not automatically deleted when group is deleted
        // This is a design decision - files may exist independently

        drop(data);
        self.persist_if_enabled().await?;
        Ok(())
    }

    async fn list_groups(&self) -> StorageResult<Vec<Group>> {
        let data = self.data.read().await;
        Ok(data.groups.values().cloned().collect())
    }

    async fn get_user_groups(&self, user_id: &Uuid) -> StorageResult<Vec<Group>> {
        let data = self.data.read().await;
        Ok(data
            .groups
            .values()
            .filter(|group| group.members.contains(user_id))
            .cloned()
            .collect())
    }

    async fn add_group_member(&self, group_id: &Uuid, user_id: &Uuid) -> StorageResult<()> {
        let mut data = self.data.write().await;

        let group = data.groups.get_mut(group_id)
            .ok_or(StorageError::GroupNotFound { id: *group_id })?;

        group.members.insert(*user_id);
        drop(data);
        self.persist_if_enabled().await?;
        Ok(())
    }

    async fn remove_group_member(&self, group_id: &Uuid, user_id: &Uuid) -> StorageResult<()> {
        let mut data = self.data.write().await;

        let group = data.groups.get_mut(group_id)
            .ok_or(StorageError::GroupNotFound { id: *group_id })?;

        // Don't allow removing the creator
        if group.created_by == *user_id {
            return Err(StorageError::permission_denied("Cannot remove group creator"));
        }

        group.members.remove(user_id);
        data.sender_keys.remove(&(*group_id, *user_id));

        drop(data);
        self.persist_if_enabled().await?;
        Ok(())
    }

    // File operations (continuing in next part due to length limit)
    async fn create_shared_file(&self, file: &SharedFile) -> StorageResult<()> {
        self.check_capacity().await?;

        let mut data = self.data.write().await;
        if data.files.contains_key(&file.id) {
            return Err(StorageError::data_integrity(format!(
                "File with ID {} already exists",
                file.id
            )));
        }

        data.files.insert(file.id, file.clone());
        drop(data);
        self.persist_if_enabled().await?;
        Ok(())
    }

    async fn get_shared_file(&self, file_id: &Uuid) -> StorageResult<SharedFile> {
        let data = self.data.read().await;
        data.files
            .get(file_id)
            .cloned()
            .ok_or(StorageError::FileNotFound { id: *file_id })
    }

    async fn update_shared_file(&self, file: &SharedFile) -> StorageResult<()> {
        let mut data = self.data.write().await;
        if !data.files.contains_key(&file.id) {
            return Err(StorageError::FileNotFound { id: file.id });
        }

        data.files.insert(file.id, file.clone());
        drop(data);
        self.persist_if_enabled().await?;
        Ok(())
    }

    async fn delete_shared_file(&self, file_id: &Uuid) -> StorageResult<()> {
        let mut data = self.data.write().await;
        if data.files.remove(file_id).is_none() {
            return Err(StorageError::FileNotFound { id: *file_id });
        }

        drop(data);
        self.persist_if_enabled().await?;
        Ok(())
    }

    async fn list_shared_files(&self) -> StorageResult<Vec<SharedFile>> {
        let data = self.data.read().await;
        Ok(data.files.values().cloned().collect())
    }

    async fn get_group_files(&self, group_id: &Uuid) -> StorageResult<Vec<SharedFile>> {
        let data = self.data.read().await;
        let group = data.groups.get(group_id)
            .ok_or(StorageError::GroupNotFound { id: *group_id })?;

        Ok(group.shared_files.clone())
    }

    async fn get_user_files(&self, user_id: &Uuid) -> StorageResult<Vec<SharedFile>> {
        let data = self.data.read().await;
        Ok(data
            .files
            .values()
            .filter(|file| file.shared_by == *user_id)
            .cloned()
            .collect())
    }

    async fn mark_file_downloaded(&self, file_id: &Uuid, user_id: &Uuid) -> StorageResult<()> {
        let mut data = self.data.write().await;
        let file = data.files.get_mut(file_id)
            .ok_or(StorageError::FileNotFound { id: *file_id })?;

        file.downloaded_by.insert(*user_id);
        drop(data);
        self.persist_if_enabled().await?;
        Ok(())
    }

    async fn update_file_status(&self, file_id: &Uuid, status: FileStatus) -> StorageResult<()> {
        let mut data = self.data.write().await;
        let file = data.files.get_mut(file_id)
            .ok_or(StorageError::FileNotFound { id: *file_id })?;

        file.status = status;
        drop(data);
        self.persist_if_enabled().await?;
        Ok(())
    }

    // Sender key operations
    async fn store_sender_key(
        &self,
        group_id: &Uuid,
        user_id: &Uuid,
        sender_key: &SenderKeyData,
    ) -> StorageResult<()> {
        let mut data = self.data.write().await;
        data.sender_keys.insert((*group_id, *user_id), sender_key.clone());
        drop(data);
        self.persist_if_enabled().await?;
        Ok(())
    }

    async fn get_sender_key(
        &self,
        group_id: &Uuid,
        user_id: &Uuid,
    ) -> StorageResult<SenderKeyData> {
        let data = self.data.read().await;
        data.sender_keys
            .get(&(*group_id, *user_id))
            .cloned()
            .ok_or(StorageError::SenderKeyNotFound {
                user_id: *user_id,
                group_id: *group_id,
            })
    }

    async fn update_sender_key(
        &self,
        group_id: &Uuid,
        user_id: &Uuid,
        sender_key: &SenderKeyData,
    ) -> StorageResult<()> {
        let mut data = self.data.write().await;
        if !data.sender_keys.contains_key(&(*group_id, *user_id)) {
            return Err(StorageError::SenderKeyNotFound {
                user_id: *user_id,
                group_id: *group_id,
            });
        }

        data.sender_keys.insert((*group_id, *user_id), sender_key.clone());
        drop(data);
        self.persist_if_enabled().await?;
        Ok(())
    }

    async fn delete_sender_key(&self, group_id: &Uuid, user_id: &Uuid) -> StorageResult<()> {
        let mut data = self.data.write().await;
        if data.sender_keys.remove(&(*group_id, *user_id)).is_none() {
            return Err(StorageError::SenderKeyNotFound {
                user_id: *user_id,
                group_id: *group_id,
            });
        }

        drop(data);
        self.persist_if_enabled().await?;
        Ok(())
    }

    async fn get_group_sender_keys(&self, group_id: &Uuid) -> StorageResult<HashMap<Uuid, SenderKeyData>> {
        let data = self.data.read().await;
        let mut result = HashMap::new();

        for ((gid, uid), key) in &data.sender_keys {
            if gid == group_id {
                result.insert(*uid, key.clone());
            }
        }

        Ok(result)
    }

    // Key bundle operations
    async fn store_key_bundle(&self, user_id: &Uuid, bundle: &PublicKeyBundle) -> StorageResult<()> {
        let mut data = self.data.write().await;
        data.key_bundles.insert(*user_id, bundle.clone());
        drop(data);
        self.persist_if_enabled().await?;
        Ok(())
    }

    async fn get_key_bundle(&self, user_id: &Uuid) -> StorageResult<PublicKeyBundle> {
        let data = self.data.read().await;
        data.key_bundles
            .get(user_id)
            .cloned()
            .ok_or(StorageError::UserNotFound { id: *user_id })
    }

    async fn update_key_bundle(&self, user_id: &Uuid, bundle: &PublicKeyBundle) -> StorageResult<()> {
        let mut data = self.data.write().await;
        if !data.key_bundles.contains_key(user_id) {
            return Err(StorageError::UserNotFound { id: *user_id });
        }

        data.key_bundles.insert(*user_id, bundle.clone());
        drop(data);
        self.persist_if_enabled().await?;
        Ok(())
    }

    async fn delete_key_bundle(&self, user_id: &Uuid) -> StorageResult<()> {
        let mut data = self.data.write().await;
        if data.key_bundles.remove(user_id).is_none() {
            return Err(StorageError::UserNotFound { id: *user_id });
        }

        drop(data);
        self.persist_if_enabled().await?;
        Ok(())
    }

    // Utility operations
    async fn get_statistics(&self) -> StorageResult<StorageStatistics> {
        let data = self.data.read().await;
        Ok(StorageStatistics {
            user_count: data.users.len() as u64,
            group_count: data.groups.len() as u64,
            file_count: data.files.len() as u64,
            sender_key_count: data.sender_keys.len() as u64,
            total_size: 0, // Memory storage doesn't track size
            encrypted_records: if self.encryption.is_some() {
                (data.users.len() + data.groups.len() + data.files.len()) as u64
            } else {
                0
            },
            last_cleanup: None,
            schema_version: 1,
        })
    }

    async fn cleanup_expired_data(&self) -> StorageResult<u64> {
        // Memory storage doesn't have expiration logic
        Ok(0)
    }

    async fn backup_to_file(&self, path: &str) -> StorageResult<()> {
        let data = self.data.read().await;
        let json = serde_json::to_string_pretty(&*data)?;
        tokio::fs::write(path, json).await?;
        Ok(())
    }

    async fn restore_from_file(&self, path: &str) -> StorageResult<()> {
        let json = tokio::fs::read_to_string(path).await?;
        let loaded_data: MemoryData = serde_json::from_str(&json)?;
        let mut data = self.data.write().await;
        *data = loaded_data;
        Ok(())
    }

    async fn optimize(&self) -> StorageResult<()> {
        // Memory storage doesn't need optimization
        Ok(())
    }
}

#[async_trait]
impl QueryableStorage for MemoryStorage {
    async fn query_users(&self, options: &QueryOptions) -> StorageResult<Vec<User>> {
        let data = self.data.read().await;
        let mut users: Vec<User> = data.users.values().cloned().collect();

        // Apply filters
        for (key, value) in &options.filters {
            users.retain(|user| match key.as_str() {
                "name" => user.name.contains(value),
                "status" => format!("{:?}", user.status).contains(value),
                _ => true,
            });
        }

        // Apply sorting
        if let Some(sort_field) = &options.sort_by {
            match sort_field.as_str() {
                "name" => users.sort_by(|a, b| {
                    if options.ascending {
                        a.name.cmp(&b.name)
                    } else {
                        b.name.cmp(&a.name)
                    }
                }),
                "created_at" => users.sort_by(|a, b| {
                    if options.ascending {
                        a.created_at.cmp(&b.created_at)
                    } else {
                        b.created_at.cmp(&a.created_at)
                    }
                }),
                _ => {}
            }
        }

        // Apply pagination
        if let Some(offset) = options.offset {
            users = users.into_iter().skip(offset as usize).collect();
        }
        if let Some(limit) = options.limit {
            users.truncate(limit as usize);
        }

        Ok(users)
    }

    async fn query_groups(&self, options: &QueryOptions) -> StorageResult<Vec<Group>> {
        let data = self.data.read().await;
        let mut groups: Vec<Group> = data.groups.values().cloned().collect();

        // Apply filters
        for (key, value) in &options.filters {
            groups.retain(|group| match key.as_str() {
                "name" => group.name.contains(value),
                _ => true,
            });
        }

        // Apply sorting
        if let Some(sort_field) = &options.sort_by {
            match sort_field.as_str() {
                "name" => groups.sort_by(|a, b| {
                    if options.ascending {
                        a.name.cmp(&b.name)
                    } else {
                        b.name.cmp(&a.name)
                    }
                }),
                "created_at" => groups.sort_by(|a, b| {
                    if options.ascending {
                        a.created_at.cmp(&b.created_at)
                    } else {
                        b.created_at.cmp(&a.created_at)
                    }
                }),
                _ => {}
            }
        }

        // Apply pagination
        if let Some(offset) = options.offset {
            groups = groups.into_iter().skip(offset as usize).collect();
        }
        if let Some(limit) = options.limit {
            groups.truncate(limit as usize);
        }

        Ok(groups)
    }

    async fn query_files(&self, options: &QueryOptions) -> StorageResult<Vec<SharedFile>> {
        let data = self.data.read().await;
        let mut files: Vec<SharedFile> = data.files.values().cloned().collect();

        // Apply filters
        for (key, value) in &options.filters {
            files.retain(|file| match key.as_str() {
                "name" => file.original_name.contains(value),
                "mime_type" => file.mime_type.contains(value),
                "status" => format!("{:?}", file.status).contains(value),
                _ => true,
            });
        }

        // Apply sorting
        if let Some(sort_field) = &options.sort_by {
            match sort_field.as_str() {
                "name" => files.sort_by(|a, b| {
                    if options.ascending {
                        a.original_name.cmp(&b.original_name)
                    } else {
                        b.original_name.cmp(&a.original_name)
                    }
                }),
                "size" => files.sort_by(|a, b| {
                    if options.ascending {
                        a.size.cmp(&b.size)
                    } else {
                        b.size.cmp(&a.size)
                    }
                }),
                "shared_at" => files.sort_by(|a, b| {
                    if options.ascending {
                        a.shared_at.cmp(&b.shared_at)
                    } else {
                        b.shared_at.cmp(&a.shared_at)
                    }
                }),
                _ => {}
            }
        }

        // Apply pagination
        if let Some(offset) = options.offset {
            files = files.into_iter().skip(offset as usize).collect();
        }
        if let Some(limit) = options.limit {
            files.truncate(limit as usize);
        }

        Ok(files)
    }

    async fn count_users(&self, filters: &HashMap<String, String>) -> StorageResult<u64> {
        let data = self.data.read().await;
        let mut count = 0u64;

        for user in data.users.values() {
            let mut matches = true;
            for (key, value) in filters {
                match key.as_str() {
                    "name" => {
                        if !user.name.contains(value) {
                            matches = false;
                            break;
                        }
                    }
                    "status" => {
                        if !format!("{:?}", user.status).contains(value) {
                            matches = false;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if matches {
                count += 1;
            }
        }

        Ok(count)
    }

    async fn count_groups(&self, filters: &HashMap<String, String>) -> StorageResult<u64> {
        let data = self.data.read().await;
        let mut count = 0u64;

        for group in data.groups.values() {
            let mut matches = true;
            for (key, value) in filters {
                match key.as_str() {
                    "name" => {
                        if !group.name.contains(value) {
                            matches = false;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if matches {
                count += 1;
            }
        }

        Ok(count)
    }

    async fn count_files(&self, filters: &HashMap<String, String>) -> StorageResult<u64> {
        let data = self.data.read().await;
        let mut count = 0u64;

        for file in data.files.values() {
            let mut matches = true;
            for (key, value) in filters {
                match key.as_str() {
                    "name" => {
                        if !file.original_name.contains(value) {
                            matches = false;
                            break;
                        }
                    }
                    "mime_type" => {
                        if !file.mime_type.contains(value) {
                            matches = false;
                            break;
                        }
                    }
                    "status" => {
                        if !format!("{:?}", file.status).contains(value) {
                            matches = false;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if matches {
                count += 1;
            }
        }

        Ok(count)
    }
}
