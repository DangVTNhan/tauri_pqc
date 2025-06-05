//! Secure storage layer for the Tauri E2EE file sharing application
//!
//! This module provides a comprehensive storage abstraction with support for:
//! - Multiple storage backends (SQLite, In-Memory)
//! - End-to-end encryption of stored data
//! - CRUD operations for all data models
//! - Transaction support
//! - Query capabilities
//! - Backup and restore functionality

pub mod commands;
pub mod config;
pub mod encryption;
pub mod error;
pub mod memory;
pub mod sqlite;
pub mod traits;
pub mod auth;

#[cfg(test)]
mod tests;

// Re-export main types
pub use config::{StorageConfig, StorageBackend, SQLiteConfig, MemoryConfig};
pub use encryption::{EncryptionService, EncryptionConfig, MasterKey, EncryptedData};
pub use error::{StorageError, StorageResult};
pub use memory::MemoryStorage;
pub use sqlite::SQLiteStorage;
pub use traits::{Storage, Transaction, StorageStatistics, QueryOptions, QueryableStorage};
pub use auth::AuthStorage;

use std::sync::Arc;

/// Storage instance enum to avoid complex trait objects
pub enum StorageInstance {
    Memory(MemoryStorage),
    SQLite(SQLiteStorage),
}

/// Transaction enum to match StorageInstance
pub enum StorageTransaction {
    Memory(Box<memory::MemoryTransaction>),
    SQLite(Box<sqlite::SQLiteTransaction>),
}

#[async_trait::async_trait]
impl Transaction for StorageTransaction {
    async fn commit(&mut self) -> StorageResult<()> {
        match self {
            StorageTransaction::Memory(tx) => tx.commit().await,
            StorageTransaction::SQLite(tx) => tx.commit().await,
        }
    }

    async fn rollback(&mut self) -> StorageResult<()> {
        match self {
            StorageTransaction::Memory(tx) => tx.rollback().await,
            StorageTransaction::SQLite(tx) => tx.rollback().await,
        }
    }
}

// Implement Storage trait for StorageInstance to delegate to the underlying storage
#[async_trait::async_trait]
impl Storage for StorageInstance {
    type Transaction = StorageTransaction;

    async fn initialize(&mut self) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.initialize().await,
            StorageInstance::SQLite(storage) => storage.initialize().await,
        }
    }

    async fn health_check(&self) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.health_check().await,
            StorageInstance::SQLite(storage) => storage.health_check().await,
        }
    }

    async fn begin_transaction(&self) -> StorageResult<Box<Self::Transaction>> {
        match self {
            StorageInstance::Memory(storage) => {
                let tx = storage.begin_transaction().await?;
                Ok(Box::new(StorageTransaction::Memory(tx)))
            },
            StorageInstance::SQLite(storage) => {
                let tx = storage.begin_transaction().await?;
                Ok(Box::new(StorageTransaction::SQLite(tx)))
            },
        }
    }

    async fn create_user(&self, user: &crate::models::User) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.create_user(user).await,
            StorageInstance::SQLite(storage) => storage.create_user(user).await,
        }
    }

    async fn get_user(&self, user_id: &uuid::Uuid) -> StorageResult<crate::models::User> {
        match self {
            StorageInstance::Memory(storage) => storage.get_user(user_id).await,
            StorageInstance::SQLite(storage) => storage.get_user(user_id).await,
        }
    }

    async fn update_user(&self, user: &crate::models::User) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.update_user(user).await,
            StorageInstance::SQLite(storage) => storage.update_user(user).await,
        }
    }

    async fn delete_user(&self, user_id: &uuid::Uuid) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.delete_user(user_id).await,
            StorageInstance::SQLite(storage) => storage.delete_user(user_id).await,
        }
    }

    async fn list_users(&self) -> StorageResult<Vec<crate::models::User>> {
        match self {
            StorageInstance::Memory(storage) => storage.list_users().await,
            StorageInstance::SQLite(storage) => storage.list_users().await,
        }
    }

    async fn find_users_by_name(&self, pattern: &str) -> StorageResult<Vec<crate::models::User>> {
        match self {
            StorageInstance::Memory(storage) => storage.find_users_by_name(pattern).await,
            StorageInstance::SQLite(storage) => storage.find_users_by_name(pattern).await,
        }
    }

    async fn get_users(&self, user_ids: &[uuid::Uuid]) -> StorageResult<Vec<crate::models::User>> {
        match self {
            StorageInstance::Memory(storage) => storage.get_users(user_ids).await,
            StorageInstance::SQLite(storage) => storage.get_users(user_ids).await,
        }
    }

    async fn create_group(&self, group: &crate::models::Group) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.create_group(group).await,
            StorageInstance::SQLite(storage) => storage.create_group(group).await,
        }
    }

    async fn get_group(&self, group_id: &uuid::Uuid) -> StorageResult<crate::models::Group> {
        match self {
            StorageInstance::Memory(storage) => storage.get_group(group_id).await,
            StorageInstance::SQLite(storage) => storage.get_group(group_id).await,
        }
    }

    async fn update_group(&self, group: &crate::models::Group) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.update_group(group).await,
            StorageInstance::SQLite(storage) => storage.update_group(group).await,
        }
    }

    async fn delete_group(&self, group_id: &uuid::Uuid) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.delete_group(group_id).await,
            StorageInstance::SQLite(storage) => storage.delete_group(group_id).await,
        }
    }

    async fn list_groups(&self) -> StorageResult<Vec<crate::models::Group>> {
        match self {
            StorageInstance::Memory(storage) => storage.list_groups().await,
            StorageInstance::SQLite(storage) => storage.list_groups().await,
        }
    }

    async fn get_user_groups(&self, user_id: &uuid::Uuid) -> StorageResult<Vec<crate::models::Group>> {
        match self {
            StorageInstance::Memory(storage) => storage.get_user_groups(user_id).await,
            StorageInstance::SQLite(storage) => storage.get_user_groups(user_id).await,
        }
    }

    async fn add_group_member(&self, group_id: &uuid::Uuid, user_id: &uuid::Uuid) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.add_group_member(group_id, user_id).await,
            StorageInstance::SQLite(storage) => storage.add_group_member(group_id, user_id).await,
        }
    }

    async fn remove_group_member(&self, group_id: &uuid::Uuid, user_id: &uuid::Uuid) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.remove_group_member(group_id, user_id).await,
            StorageInstance::SQLite(storage) => storage.remove_group_member(group_id, user_id).await,
        }
    }

    async fn create_shared_file(&self, file: &crate::models::SharedFile) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.create_shared_file(file).await,
            StorageInstance::SQLite(storage) => storage.create_shared_file(file).await,
        }
    }

    async fn get_shared_file(&self, file_id: &uuid::Uuid) -> StorageResult<crate::models::SharedFile> {
        match self {
            StorageInstance::Memory(storage) => storage.get_shared_file(file_id).await,
            StorageInstance::SQLite(storage) => storage.get_shared_file(file_id).await,
        }
    }

    async fn update_shared_file(&self, file: &crate::models::SharedFile) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.update_shared_file(file).await,
            StorageInstance::SQLite(storage) => storage.update_shared_file(file).await,
        }
    }

    async fn delete_shared_file(&self, file_id: &uuid::Uuid) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.delete_shared_file(file_id).await,
            StorageInstance::SQLite(storage) => storage.delete_shared_file(file_id).await,
        }
    }

    async fn list_shared_files(&self) -> StorageResult<Vec<crate::models::SharedFile>> {
        match self {
            StorageInstance::Memory(storage) => storage.list_shared_files().await,
            StorageInstance::SQLite(storage) => storage.list_shared_files().await,
        }
    }

    async fn get_group_files(&self, group_id: &uuid::Uuid) -> StorageResult<Vec<crate::models::SharedFile>> {
        match self {
            StorageInstance::Memory(storage) => storage.get_group_files(group_id).await,
            StorageInstance::SQLite(storage) => storage.get_group_files(group_id).await,
        }
    }

    async fn get_user_files(&self, user_id: &uuid::Uuid) -> StorageResult<Vec<crate::models::SharedFile>> {
        match self {
            StorageInstance::Memory(storage) => storage.get_user_files(user_id).await,
            StorageInstance::SQLite(storage) => storage.get_user_files(user_id).await,
        }
    }

    async fn mark_file_downloaded(&self, file_id: &uuid::Uuid, user_id: &uuid::Uuid) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.mark_file_downloaded(file_id, user_id).await,
            StorageInstance::SQLite(storage) => storage.mark_file_downloaded(file_id, user_id).await,
        }
    }

    async fn update_file_status(&self, file_id: &uuid::Uuid, status: crate::models::FileStatus) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.update_file_status(file_id, status).await,
            StorageInstance::SQLite(storage) => storage.update_file_status(file_id, status).await,
        }
    }

    async fn store_sender_key(&self, group_id: &uuid::Uuid, user_id: &uuid::Uuid, sender_key: &crate::models::SenderKeyData) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.store_sender_key(group_id, user_id, sender_key).await,
            StorageInstance::SQLite(storage) => storage.store_sender_key(group_id, user_id, sender_key).await,
        }
    }

    async fn get_sender_key(&self, group_id: &uuid::Uuid, user_id: &uuid::Uuid) -> StorageResult<crate::models::SenderKeyData> {
        match self {
            StorageInstance::Memory(storage) => storage.get_sender_key(group_id, user_id).await,
            StorageInstance::SQLite(storage) => storage.get_sender_key(group_id, user_id).await,
        }
    }

    async fn update_sender_key(&self, group_id: &uuid::Uuid, user_id: &uuid::Uuid, sender_key: &crate::models::SenderKeyData) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.update_sender_key(group_id, user_id, sender_key).await,
            StorageInstance::SQLite(storage) => storage.update_sender_key(group_id, user_id, sender_key).await,
        }
    }

    async fn delete_sender_key(&self, group_id: &uuid::Uuid, user_id: &uuid::Uuid) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.delete_sender_key(group_id, user_id).await,
            StorageInstance::SQLite(storage) => storage.delete_sender_key(group_id, user_id).await,
        }
    }

    async fn get_group_sender_keys(&self, group_id: &uuid::Uuid) -> StorageResult<std::collections::HashMap<uuid::Uuid, crate::models::SenderKeyData>> {
        match self {
            StorageInstance::Memory(storage) => storage.get_group_sender_keys(group_id).await,
            StorageInstance::SQLite(storage) => storage.get_group_sender_keys(group_id).await,
        }
    }

    async fn store_key_bundle(&self, user_id: &uuid::Uuid, bundle: &crate::models::PublicKeyBundle) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.store_key_bundle(user_id, bundle).await,
            StorageInstance::SQLite(storage) => storage.store_key_bundle(user_id, bundle).await,
        }
    }

    async fn get_key_bundle(&self, user_id: &uuid::Uuid) -> StorageResult<crate::models::PublicKeyBundle> {
        match self {
            StorageInstance::Memory(storage) => storage.get_key_bundle(user_id).await,
            StorageInstance::SQLite(storage) => storage.get_key_bundle(user_id).await,
        }
    }

    async fn update_key_bundle(&self, user_id: &uuid::Uuid, bundle: &crate::models::PublicKeyBundle) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.update_key_bundle(user_id, bundle).await,
            StorageInstance::SQLite(storage) => storage.update_key_bundle(user_id, bundle).await,
        }
    }

    async fn delete_key_bundle(&self, user_id: &uuid::Uuid) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.delete_key_bundle(user_id).await,
            StorageInstance::SQLite(storage) => storage.delete_key_bundle(user_id).await,
        }
    }

    async fn get_statistics(&self) -> StorageResult<StorageStatistics> {
        match self {
            StorageInstance::Memory(storage) => storage.get_statistics().await,
            StorageInstance::SQLite(storage) => storage.get_statistics().await,
        }
    }

    async fn cleanup_expired_data(&self) -> StorageResult<u64> {
        match self {
            StorageInstance::Memory(storage) => storage.cleanup_expired_data().await,
            StorageInstance::SQLite(storage) => storage.cleanup_expired_data().await,
        }
    }

    async fn backup_to_file(&self, path: &str) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.backup_to_file(path).await,
            StorageInstance::SQLite(storage) => storage.backup_to_file(path).await,
        }
    }

    async fn restore_from_file(&self, path: &str) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.restore_from_file(path).await,
            StorageInstance::SQLite(storage) => storage.restore_from_file(path).await,
        }
    }

    async fn optimize(&self) -> StorageResult<()> {
        match self {
            StorageInstance::Memory(storage) => storage.optimize().await,
            StorageInstance::SQLite(storage) => storage.optimize().await,
        }
    }
}

/// Storage factory for creating storage instances
pub struct StorageFactory;

impl StorageFactory {
    /// Create a new storage instance based on configuration
    pub async fn create(config: StorageConfig) -> StorageResult<StorageInstance> {
        config.validate()?;
        config.ensure_directories()?;

        match config.backend {
            StorageBackend::Memory => {
                let storage = if config.encryption.memory_cost > 0 {
                    // Create with encryption
                    let encryption = EncryptionService::new();
                    MemoryStorage::with_encryption(config.memory, encryption)
                } else {
                    MemoryStorage::new(config.memory)
                };

                let mut storage = storage;
                storage.initialize().await?;
                Ok(StorageInstance::Memory(storage))
            }
            StorageBackend::SQLite => {
                let storage = if config.encryption.memory_cost > 0 {
                    // Create with encryption
                    let encryption = EncryptionService::new();
                    SQLiteStorage::with_encryption(config.sqlite, encryption).await?
                } else {
                    SQLiteStorage::new(config.sqlite).await?
                };

                let mut storage = storage;
                storage.initialize().await?;
                Ok(StorageInstance::SQLite(storage))
            }
        }
    }

    /// Create a storage instance with password-based encryption
    pub async fn create_with_password(
        config: StorageConfig,
        password: &str,
        salt: &[u8],
    ) -> StorageResult<StorageInstance> {
        config.validate()?;
        config.ensure_directories()?;

        let encryption = EncryptionService::with_password(password, salt, config.encryption.clone())?;

        match config.backend {
            StorageBackend::Memory => {
                let storage = MemoryStorage::with_encryption(config.memory, encryption);
                let mut storage = storage;
                storage.initialize().await?;
                Ok(StorageInstance::Memory(storage))
            }
            StorageBackend::SQLite => {
                let storage = SQLiteStorage::with_encryption(config.sqlite, encryption).await?;
                let mut storage = storage;
                storage.initialize().await?;
                Ok(StorageInstance::SQLite(storage))
            }
        }
    }

    /// Create a storage instance with existing master key
    pub async fn create_with_master_key(
        config: StorageConfig,
        master_key: MasterKey,
    ) -> StorageResult<StorageInstance> {
        config.validate()?;
        config.ensure_directories()?;

        let encryption = EncryptionService::with_master_key(master_key);

        match config.backend {
            StorageBackend::Memory => {
                let storage = MemoryStorage::with_encryption(config.memory, encryption);
                let mut storage = storage;
                storage.initialize().await?;
                Ok(StorageInstance::Memory(storage))
            }
            StorageBackend::SQLite => {
                let storage = SQLiteStorage::with_encryption(config.sqlite, encryption).await?;
                let mut storage = storage;
                storage.initialize().await?;
                Ok(StorageInstance::SQLite(storage))
            }
        }
    }

    /// Create an unencrypted storage instance (for testing only)
    pub async fn create_unencrypted(config: StorageConfig) -> StorageResult<StorageInstance> {
        config.validate()?;
        config.ensure_directories()?;

        match config.backend {
            StorageBackend::Memory => {
                let storage = MemoryStorage::new(config.memory);
                let mut storage = storage;
                storage.initialize().await?;
                Ok(StorageInstance::Memory(storage))
            }
            StorageBackend::SQLite => {
                let storage = SQLiteStorage::new(config.sqlite).await?;
                let mut storage = storage;
                storage.initialize().await?;
                Ok(StorageInstance::SQLite(storage))
            }
        }
    }
}

/// Storage manager for handling multiple storage instances
pub struct StorageManager {
    primary: StorageInstance,
    backup: Option<StorageInstance>,
    config: StorageConfig,
}

impl StorageManager {
    /// Create a new storage manager
    pub async fn new(config: StorageConfig) -> StorageResult<Self> {
        let primary = StorageFactory::create(config.clone()).await?;

        Ok(Self {
            primary,
            backup: None,
            config,
        })
    }

    /// Create a storage manager with password-based encryption
    pub async fn with_password(
        config: StorageConfig,
        password: &str,
        salt: &[u8],
    ) -> StorageResult<Self> {
        let primary = StorageFactory::create_with_password(config.clone(), password, salt).await?;

        Ok(Self {
            primary,
            backup: None,
            config,
        })
    }

    /// Add a backup storage instance
    pub async fn with_backup(mut self, backup_config: StorageConfig) -> StorageResult<Self> {
        let backup = StorageFactory::create(backup_config).await?;
        self.backup = Some(backup);
        Ok(self)
    }

    /// Get the primary storage instance
    pub fn primary(&self) -> &StorageInstance {
        &self.primary
    }

    /// Get the backup storage instance
    pub fn backup(&self) -> Option<&StorageInstance> {
        self.backup.as_ref()
    }

    /// Perform health check on all storage instances
    pub async fn health_check(&self) -> StorageResult<()> {
        self.primary.health_check().await?;

        if let Some(backup) = &self.backup {
            backup.health_check().await?;
        }

        Ok(())
    }

    /// Sync data from primary to backup storage
    pub async fn sync_to_backup(&self) -> StorageResult<()> {
        if let Some(backup) = &self.backup {
            // Get all data from primary
            let users = self.primary.list_users().await?;
            let groups = self.primary.list_groups().await?;
            let files = self.primary.list_shared_files().await?;

            // Store in backup
            for user in users {
                if backup.create_user(&user).await.is_err() {
                    backup.update_user(&user).await?;
                }
            }

            for group in groups {
                if backup.create_group(&group).await.is_err() {
                    backup.update_group(&group).await?;
                }
            }

            for file in files {
                if backup.create_shared_file(&file).await.is_err() {
                    backup.update_shared_file(&file).await?;
                }
            }
        }

        Ok(())
    }

    /// Get storage statistics from all instances
    pub async fn get_all_statistics(&self) -> StorageResult<(StorageStatistics, Option<StorageStatistics>)> {
        let primary_stats = self.primary.get_statistics().await?;

        let backup_stats = if let Some(backup) = &self.backup {
            Some(backup.get_statistics().await?)
        } else {
            None
        };

        Ok((primary_stats, backup_stats))
    }

    /// Cleanup expired data from all storage instances
    pub async fn cleanup_all(&self) -> StorageResult<(u64, Option<u64>)> {
        let primary_cleaned = self.primary.cleanup_expired_data().await?;

        let backup_cleaned = if let Some(backup) = &self.backup {
            Some(backup.cleanup_expired_data().await?)
        } else {
            None
        };

        Ok((primary_cleaned, backup_cleaned))
    }

    /// Optimize all storage instances
    pub async fn optimize_all(&self) -> StorageResult<()> {
        self.primary.optimize().await?;

        if let Some(backup) = &self.backup {
            backup.optimize().await?;
        }

        Ok(())
    }

    /// Create a backup of all data to file
    pub async fn backup_to_file(&self, path: &str) -> StorageResult<()> {
        self.primary.backup_to_file(path).await
    }

    /// Restore data from file to primary storage
    pub async fn restore_from_file(&self, path: &str) -> StorageResult<()> {
        self.primary.restore_from_file(path).await
    }

    /// Get the storage configuration
    pub fn config(&self) -> &StorageConfig {
        &self.config
    }
}

/// Utility functions for storage operations
pub mod utils {
    use super::*;
    use crate::models::demo::Demo;

    /// Initialize storage with demo data
    pub async fn init_with_demo_data(
        storage: &StorageInstance,
    ) -> StorageResult<()> {
        let scenario = Demo::create_demo_scenario();

        // Create users
        for user in &scenario.users {
            storage.create_user(user).await?;
        }

        // Create group
        storage.create_group(&scenario.group).await?;

        // Store sender keys
        for (user_id, sender_key) in &scenario.group.sender_keys {
            storage.store_sender_key(&scenario.group.id, user_id, sender_key).await?;
        }

        // Store key bundles
        for user in &scenario.users {
            if let Some(bundle) = user.get_public_key_bundle() {
                storage.store_key_bundle(&user.id, &bundle).await?;
            }
        }

        Ok(())
    }

    /// Validate storage integrity
    pub async fn validate_storage_integrity(
        storage: &StorageInstance,
    ) -> StorageResult<bool> {
        // Check if all users have valid data
        let users = storage.list_users().await?;
        for user in &users {
            // Verify user can be retrieved
            let retrieved_user = storage.get_user(&user.id).await?;
            if retrieved_user.id != user.id {
                return Ok(false);
            }
        }

        // Check if all groups have valid data
        let groups = storage.list_groups().await?;
        for group in &groups {
            // Verify group can be retrieved
            let retrieved_group = storage.get_group(&group.id).await?;
            if retrieved_group.id != group.id {
                return Ok(false);
            }

            // Verify all members exist
            for member_id in &group.members {
                storage.get_user(member_id).await?;
            }
        }

        Ok(true)
    }
}
