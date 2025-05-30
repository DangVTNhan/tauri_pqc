//! Comprehensive tests for the storage layer
//!
//! This module contains tests for:
//! - Memory storage implementation
//! - SQLite storage implementation
//! - Encryption functionality
//! - Transaction handling
//! - Error conditions
//! - Data integrity

use super::*;
use crate::models::{User, Group, SharedFile, UserStatus, FileStatus, GroupSettings};
use chrono::Utc;
use std::collections::HashSet;
use tempfile::TempDir;
use uuid::Uuid;

/// Helper function to create a test user
fn create_test_user(name: &str) -> User {
    User {
        id: Uuid::new_v4(),
        name: name.to_string(),
        registration_id: 12345,
        device_id: 1,
        created_at: Utc::now(),
        status: UserStatus::Active,
        identity_key_pair: None,
        signed_pre_key: None,
        kyber_pre_key: None,
        one_time_pre_keys: Vec::new(),
        group_memberships: HashSet::new(),
        preferences: crate::models::UserPreferences {
            auto_download_files: true,
            max_auto_download_size: 100 * 1024 * 1024, // 100MB
            show_download_notifications: true,
            download_directory: Some("/tmp/downloads".to_string()),
            auto_verify_files: true,
        },
    }
}

/// Helper function to create a test group
fn create_test_group(name: &str, creator_id: Uuid) -> Group {
    Group {
        id: Uuid::new_v4(),
        name: name.to_string(),
        created_by: creator_id,
        created_at: Utc::now(),
        members: {
            let mut members = HashSet::new();
            members.insert(creator_id);
            members
        },
        sender_keys: std::collections::HashMap::new(),
        shared_files: Vec::new(),
        settings: GroupSettings {
            max_file_size: 100 * 1024 * 1024, // 100MB
            allow_historical_access: true,
            allow_member_invites: false,
            file_retention_days: 30,
        },
    }
}

/// Helper function to create a test shared file
fn create_test_file(name: &str, shared_by: Uuid) -> SharedFile {
    SharedFile {
        id: Uuid::new_v4(),
        original_name: name.to_string(),
        encrypted_name: format!("encrypted_{}", name),
        size: 1024,
        mime_type: "text/plain".to_string(),
        shared_by,
        shared_at: Utc::now(),
        encryption_metadata: crate::models::FileEncryptionMetadata {
            encryption_key: vec![0u8; 32],
            iv: vec![0u8; 12],
            auth_tag: vec![0u8; 16],
            chunk_size: 1024,
            total_chunks: 1,
            algorithm: "AES-256-GCM".to_string(),
            key_derivation: crate::models::KeyDerivationParams::default(),
            original_checksum: vec![0u8; 32],
            checksum_algorithm: "SHA-256".to_string(),
        },
        downloaded_by: HashSet::new(),
        status: FileStatus::Available,
        description: Some("Test file".to_string()),
        storage_path: Some("/tmp/test_file".to_string()),
    }
}

#[cfg(test)]
mod memory_storage_tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_storage_initialization() {
        let config = MemoryConfig::default();
        let mut storage = MemoryStorage::new(config);

        assert!(storage.initialize().await.is_ok());
        assert!(storage.health_check().await.is_ok());
    }

    #[tokio::test]
    async fn test_memory_storage_user_operations() {
        let config = MemoryConfig::default();
        let mut storage = MemoryStorage::new(config);
        storage.initialize().await.unwrap();

        let user = create_test_user("Alice");
        let user_id = user.id;

        // Test create user
        assert!(storage.create_user(&user).await.is_ok());

        // Test get user
        let retrieved_user = storage.get_user(&user_id).await.unwrap();
        assert_eq!(retrieved_user.id, user.id);
        assert_eq!(retrieved_user.name, user.name);

        // Test update user
        let mut updated_user = user.clone();
        updated_user.name = "Alice Updated".to_string();
        assert!(storage.update_user(&updated_user).await.is_ok());

        let retrieved_updated = storage.get_user(&user_id).await.unwrap();
        assert_eq!(retrieved_updated.name, "Alice Updated");

        // Test list users
        let users = storage.list_users().await.unwrap();
        assert_eq!(users.len(), 1);

        // Test find users by name
        let found_users = storage.find_users_by_name("Alice").await.unwrap();
        assert_eq!(found_users.len(), 1);

        // Test delete user
        assert!(storage.delete_user(&user_id).await.is_ok());
        assert!(storage.get_user(&user_id).await.is_err());
    }

    #[tokio::test]
    async fn test_memory_storage_group_operations() {
        let config = MemoryConfig::default();
        let mut storage = MemoryStorage::new(config);
        storage.initialize().await.unwrap();

        let user = create_test_user("Alice");
        storage.create_user(&user).await.unwrap();

        let group = create_test_group("Test Group", user.id);
        let group_id = group.id;

        // Test create group
        assert!(storage.create_group(&group).await.is_ok());

        // Test get group
        let retrieved_group = storage.get_group(&group_id).await.unwrap();
        assert_eq!(retrieved_group.id, group.id);
        assert_eq!(retrieved_group.name, group.name);

        // Test update group
        let mut updated_group = group.clone();
        updated_group.name = "Updated Group".to_string();
        assert!(storage.update_group(&updated_group).await.is_ok());

        // Test list groups
        let groups = storage.list_groups().await.unwrap();
        assert_eq!(groups.len(), 1);

        // Test get user groups
        let user_groups = storage.get_user_groups(&user.id).await.unwrap();
        assert_eq!(user_groups.len(), 1);

        // Test add group member
        let new_user = create_test_user("Bob");
        storage.create_user(&new_user).await.unwrap();
        assert!(storage.add_group_member(&group_id, &new_user.id).await.is_ok());

        let updated_group = storage.get_group(&group_id).await.unwrap();
        assert!(updated_group.members.contains(&new_user.id));

        // Test remove group member
        assert!(storage.remove_group_member(&group_id, &new_user.id).await.is_ok());

        let updated_group = storage.get_group(&group_id).await.unwrap();
        assert!(!updated_group.members.contains(&new_user.id));

        // Test delete group
        assert!(storage.delete_group(&group_id).await.is_ok());
        assert!(storage.get_group(&group_id).await.is_err());
    }

    #[tokio::test]
    async fn test_memory_storage_file_operations() {
        let config = MemoryConfig::default();
        let mut storage = MemoryStorage::new(config);
        storage.initialize().await.unwrap();

        let user = create_test_user("Alice");
        storage.create_user(&user).await.unwrap();

        let file = create_test_file("test.txt", user.id);
        let file_id = file.id;

        // Test create shared file
        assert!(storage.create_shared_file(&file).await.is_ok());

        // Test get shared file
        let retrieved_file = storage.get_shared_file(&file_id).await.unwrap();
        assert_eq!(retrieved_file.id, file.id);
        assert_eq!(retrieved_file.original_name, file.original_name);

        // Test update shared file
        let mut updated_file = file.clone();
        updated_file.description = Some("Updated description".to_string());
        assert!(storage.update_shared_file(&updated_file).await.is_ok());

        // Test list shared files
        let files = storage.list_shared_files().await.unwrap();
        assert_eq!(files.len(), 1);

        // Test get user files
        let user_files = storage.get_user_files(&user.id).await.unwrap();
        assert_eq!(user_files.len(), 1);

        // Test mark file downloaded
        assert!(storage.mark_file_downloaded(&file_id, &user.id).await.is_ok());

        let updated_file = storage.get_shared_file(&file_id).await.unwrap();
        assert!(updated_file.downloaded_by.contains(&user.id));

        // Test update file status
        assert!(storage.update_file_status(&file_id, FileStatus::Expired).await.is_ok());

        let updated_file = storage.get_shared_file(&file_id).await.unwrap();
        assert_eq!(updated_file.status, FileStatus::Expired);

        // Test delete shared file
        assert!(storage.delete_shared_file(&file_id).await.is_ok());
        assert!(storage.get_shared_file(&file_id).await.is_err());
    }

    #[tokio::test]
    async fn test_memory_storage_transactions() {
        let config = MemoryConfig::default();
        let mut storage = MemoryStorage::new(config);
        storage.initialize().await.unwrap();

        let user = create_test_user("Alice");

        // Test successful transaction
        {
            let mut tx = storage.begin_transaction().await.unwrap();
            // Note: In a real implementation, we'd need to modify the transaction
            // to support operations. For now, just test commit/rollback.
            assert!(tx.commit().await.is_ok());
        }

        // Test rollback transaction
        {
            let mut tx = storage.begin_transaction().await.unwrap();
            assert!(tx.rollback().await.is_ok());
        }
    }

    #[tokio::test]
    async fn test_memory_storage_statistics() {
        let config = MemoryConfig::default();
        let mut storage = MemoryStorage::new(config);
        storage.initialize().await.unwrap();

        let user = create_test_user("Alice");
        storage.create_user(&user).await.unwrap();

        let group = create_test_group("Test Group", user.id);
        storage.create_group(&group).await.unwrap();

        let file = create_test_file("test.txt", user.id);
        storage.create_shared_file(&file).await.unwrap();

        let stats = storage.get_statistics().await.unwrap();
        assert_eq!(stats.user_count, 1);
        assert_eq!(stats.group_count, 1);
        assert_eq!(stats.file_count, 1);
    }

    #[tokio::test]
    async fn test_memory_storage_error_conditions() {
        let config = MemoryConfig::default();
        let mut storage = MemoryStorage::new(config);
        storage.initialize().await.unwrap();

        let non_existent_id = Uuid::new_v4();

        // Test getting non-existent user
        assert!(storage.get_user(&non_existent_id).await.is_err());

        // Test getting non-existent group
        assert!(storage.get_group(&non_existent_id).await.is_err());

        // Test getting non-existent file
        assert!(storage.get_shared_file(&non_existent_id).await.is_err());

        // Test deleting non-existent user
        assert!(storage.delete_user(&non_existent_id).await.is_err());

        // Test updating non-existent user
        let user = create_test_user("Alice");
        assert!(storage.update_user(&user).await.is_err());
    }
}

#[cfg(test)]
mod sqlite_storage_tests {
    use super::*;

    async fn create_test_sqlite_storage() -> SQLiteStorage {
        // Use in-memory SQLite database for testing
        let config = SQLiteConfig {
            database_path: ":memory:".into(),
            max_connections: 1, // In-memory databases should use single connection
            connection_timeout: 30,
            enable_wal: false, // WAL not supported for in-memory databases
            enable_foreign_keys: true,
            journal_mode: "MEMORY".to_string(), // Use MEMORY mode for in-memory DB
            synchronous: "OFF".to_string(), // Faster for tests
            cache_size: 1024,
            page_size: 4096,
            auto_vacuum: "NONE".to_string(), // Not needed for in-memory
        };

        let mut storage = SQLiteStorage::new(config).await.unwrap();
        storage.initialize().await.unwrap();

        storage
    }

    #[tokio::test]
    async fn test_sqlite_storage_initialization() {
        let _storage = create_test_sqlite_storage().await;
        // If we get here without panicking, initialization worked
    }

    #[tokio::test]
    async fn test_sqlite_storage_user_operations() {
        let storage = create_test_sqlite_storage().await;

        let user = create_test_user("Alice");
        let user_id = user.id;

        // Test create user
        assert!(storage.create_user(&user).await.is_ok());

        // Test get user
        let retrieved_user = storage.get_user(&user_id).await.unwrap();
        assert_eq!(retrieved_user.id, user.id);
        assert_eq!(retrieved_user.name, user.name);

        // Test update user
        let mut updated_user = user.clone();
        updated_user.name = "Alice Updated".to_string();
        assert!(storage.update_user(&updated_user).await.is_ok());

        let retrieved_updated = storage.get_user(&user_id).await.unwrap();
        assert_eq!(retrieved_updated.name, "Alice Updated");

        // Test list users
        let users = storage.list_users().await.unwrap();
        assert_eq!(users.len(), 1);

        // Test find users by name
        let found_users = storage.find_users_by_name("Alice").await.unwrap();
        assert_eq!(found_users.len(), 1);

        // Test delete user
        assert!(storage.delete_user(&user_id).await.is_ok());
        assert!(storage.get_user(&user_id).await.is_err());
    }

    #[tokio::test]
    async fn test_sqlite_storage_group_operations() {
        let storage = create_test_sqlite_storage().await;

        let user = create_test_user("Alice");
        storage.create_user(&user).await.unwrap();

        let group = create_test_group("Test Group", user.id);
        let group_id = group.id;

        // Test create group
        assert!(storage.create_group(&group).await.is_ok());

        // Test get group
        let retrieved_group = storage.get_group(&group_id).await.unwrap();
        assert_eq!(retrieved_group.id, group.id);
        assert_eq!(retrieved_group.name, group.name);

        // Test update group
        let mut updated_group = group.clone();
        updated_group.name = "Updated Group".to_string();
        assert!(storage.update_group(&updated_group).await.is_ok());

        // Test list groups
        let groups = storage.list_groups().await.unwrap();
        assert_eq!(groups.len(), 1);

        // Test get user groups
        let user_groups = storage.get_user_groups(&user.id).await.unwrap();
        assert_eq!(user_groups.len(), 1);

        // Test add group member
        let new_user = create_test_user("Bob");
        storage.create_user(&new_user).await.unwrap();
        assert!(storage.add_group_member(&group_id, &new_user.id).await.is_ok());

        let updated_group = storage.get_group(&group_id).await.unwrap();
        assert!(updated_group.members.contains(&new_user.id));

        // Test remove group member
        assert!(storage.remove_group_member(&group_id, &new_user.id).await.is_ok());

        let updated_group = storage.get_group(&group_id).await.unwrap();
        assert!(!updated_group.members.contains(&new_user.id));

        // Test delete group
        assert!(storage.delete_group(&group_id).await.is_ok());
        assert!(storage.get_group(&group_id).await.is_err());
    }

    #[tokio::test]
    async fn test_sqlite_storage_health_check() {
        let storage = create_test_sqlite_storage().await;
        assert!(storage.health_check().await.is_ok());
    }

    #[tokio::test]
    async fn test_sqlite_storage_transactions() {
        let storage = create_test_sqlite_storage().await;

        // Test successful transaction
        {
            let mut tx = storage.begin_transaction().await.unwrap();
            assert!(tx.commit().await.is_ok());
        }

        // Test rollback transaction
        {
            let mut tx = storage.begin_transaction().await.unwrap();
            assert!(tx.rollback().await.is_ok());
        }
    }
}

#[cfg(test)]
mod encryption_tests {
    use super::*;

    #[test]
    fn test_master_key_generation() {
        let key1 = MasterKey::generate();
        let key2 = MasterKey::generate();

        // Keys should be different (very high probability)
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_encryption_service_creation() {
        let service = EncryptionService::new();
        assert!(service.config().memory_cost > 0);
    }

    #[test]
    fn test_encryption_decryption() {
        let service = EncryptionService::new();
        let plaintext = b"Hello, World! This is a test message.";

        let encrypted = service.encrypt(plaintext).unwrap();
        assert_ne!(encrypted.ciphertext, plaintext);
        assert_eq!(encrypted.algorithm, "AES-256-GCM");
        assert_eq!(encrypted.nonce.len(), 12); // AES-GCM nonce size

        let decrypted = service.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_serialize_encryption() {
        let service = EncryptionService::new();
        let data = vec!["test", "data", "for", "encryption"];

        let encrypted = service.encrypt_serialize(&data).unwrap();
        let decrypted: Vec<String> = service.decrypt_deserialize(&encrypted).unwrap();

        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_encryption_with_different_services() {
        let service1 = EncryptionService::new();
        let service2 = EncryptionService::new();
        let plaintext = b"Test message";

        let encrypted1 = service1.encrypt(plaintext).unwrap();
        let encrypted2 = service2.encrypt(plaintext).unwrap();

        // Different services should produce different ciphertexts
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);

        // Each service should be able to decrypt its own data
        assert_eq!(service1.decrypt(&encrypted1).unwrap(), plaintext);
        assert_eq!(service2.decrypt(&encrypted2).unwrap(), plaintext);

        // Services should not be able to decrypt each other's data
        assert!(service1.decrypt(&encrypted2).is_err());
        assert!(service2.decrypt(&encrypted1).is_err());
    }

    #[test]
    fn test_salt_generation() {
        let salt1 = EncryptionService::generate_salt();
        let salt2 = EncryptionService::generate_salt();

        // Salts should be different
        assert_ne!(salt1, salt2);
        assert_eq!(salt1.len(), 32); // SALT_SIZE
    }

    #[test]
    fn test_invalid_nonce_size() {
        let service = EncryptionService::new();
        let invalid_encrypted = EncryptedData {
            ciphertext: vec![1, 2, 3, 4],
            nonce: vec![1, 2, 3], // Invalid nonce size (should be 12)
            salt: None,
            algorithm: "AES-256-GCM".to_string(),
        };

        assert!(service.decrypt(&invalid_encrypted).is_err());
    }
}

#[cfg(test)]
mod storage_factory_tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_storage_factory() {
        let config = StorageConfig {
            backend: StorageBackend::Memory,
            enable_auto_backup: false, // Disable backup for tests
            ..StorageConfig::default()
        };

        let storage = StorageFactory::create(config).await.unwrap();

        match storage {
            StorageInstance::Memory(_) => {}, // Expected
            StorageInstance::SQLite(_) => panic!("Expected memory storage"),
        }
    }

    #[tokio::test]
    async fn test_sqlite_storage_factory() {
        let config = StorageConfig {
            backend: StorageBackend::SQLite,
            sqlite: SQLiteConfig {
                database_path: ":memory:".into(),
                max_connections: 1,
                enable_wal: false,
                journal_mode: "MEMORY".to_string(),
                synchronous: "OFF".to_string(),
                auto_vacuum: "NONE".to_string(),
                ..SQLiteConfig::default()
            },
            enable_auto_backup: false, // Disable backup for tests
            ..StorageConfig::default()
        };

        let storage = StorageFactory::create(config).await.unwrap();

        match storage {
            StorageInstance::SQLite(_) => {}, // Expected
            StorageInstance::Memory(_) => panic!("Expected SQLite storage"),
        }
    }

    #[tokio::test]
    async fn test_storage_factory_with_encryption() {
        let config = StorageConfig {
            backend: StorageBackend::Memory,
            encryption: EncryptionConfig {
                memory_cost: 1024,
                time_cost: 1,
                parallelism: 1,
            },
            enable_auto_backup: false, // Disable backup for tests
            ..StorageConfig::default()
        };

        let password = "test_password";
        let salt = EncryptionService::generate_salt();

        let storage = StorageFactory::create_with_password(config, password, &salt).await.unwrap();

        match storage {
            StorageInstance::Memory(_) => {}, // Expected
            StorageInstance::SQLite(_) => panic!("Expected memory storage"),
        }
    }
}

#[cfg(test)]
mod storage_manager_tests {
    use super::*;

    #[tokio::test]
    async fn test_storage_manager_creation() {
        let config = StorageConfig {
            backend: StorageBackend::Memory,
            enable_auto_backup: false, // Disable backup for tests
            ..StorageConfig::default()
        };

        let manager = StorageManager::new(config).await.unwrap();
        assert!(manager.health_check().await.is_ok());
    }

    #[tokio::test]
    async fn test_storage_manager_with_password() {
        let config = StorageConfig {
            backend: StorageBackend::Memory,
            encryption: EncryptionConfig {
                memory_cost: 1024,
                time_cost: 1,
                parallelism: 1,
            },
            enable_auto_backup: false, // Disable backup for tests
            ..StorageConfig::default()
        };

        let password = "test_password";
        let salt = EncryptionService::generate_salt();

        let manager = StorageManager::with_password(config, password, &salt).await.unwrap();
        assert!(manager.health_check().await.is_ok());
    }

    #[tokio::test]
    async fn test_storage_manager_statistics() {
        let config = StorageConfig {
            backend: StorageBackend::Memory,
            enable_auto_backup: false, // Disable backup for tests
            ..StorageConfig::default()
        };

        let manager = StorageManager::new(config).await.unwrap();

        // Add some test data
        let user = create_test_user("Alice");
        manager.primary().create_user(&user).await.unwrap();

        let (stats, backup_stats) = manager.get_all_statistics().await.unwrap();
        assert_eq!(stats.user_count, 1);
        assert!(backup_stats.is_none()); // No backup configured
    }

    #[tokio::test]
    async fn test_storage_manager_cleanup() {
        let config = StorageConfig {
            backend: StorageBackend::Memory,
            enable_auto_backup: false, // Disable backup for tests
            ..StorageConfig::default()
        };

        let manager = StorageManager::new(config).await.unwrap();
        let (cleaned, backup_cleaned) = manager.cleanup_all().await.unwrap();

        assert_eq!(cleaned, 0); // No expired data in memory storage
        assert!(backup_cleaned.is_none()); // No backup configured
    }

    #[tokio::test]
    async fn test_storage_manager_optimize() {
        let config = StorageConfig {
            backend: StorageBackend::Memory,
            enable_auto_backup: false, // Disable backup for tests
            ..StorageConfig::default()
        };

        let manager = StorageManager::new(config).await.unwrap();
        assert!(manager.optimize_all().await.is_ok());
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_end_to_end_user_workflow() {
        let config = StorageConfig {
            backend: StorageBackend::Memory,
            enable_auto_backup: false, // Disable backup for tests
            ..StorageConfig::default()
        };

        let storage = StorageFactory::create(config).await.unwrap();

        // Create users
        let alice = create_test_user("Alice");
        let bob = create_test_user("Bob");

        storage.create_user(&alice).await.unwrap();
        storage.create_user(&bob).await.unwrap();

        // Create group with Alice as creator
        let group = create_test_group("Test Group", alice.id);
        storage.create_group(&group).await.unwrap();

        // Add Bob to the group
        storage.add_group_member(&group.id, &bob.id).await.unwrap();

        // Verify group membership
        let updated_group = storage.get_group(&group.id).await.unwrap();
        assert!(updated_group.members.contains(&alice.id));
        assert!(updated_group.members.contains(&bob.id));

        // Alice shares a file
        let file = create_test_file("document.pdf", alice.id);
        storage.create_shared_file(&file).await.unwrap();

        // Bob downloads the file
        storage.mark_file_downloaded(&file.id, &bob.id).await.unwrap();

        // Verify download tracking
        let updated_file = storage.get_shared_file(&file.id).await.unwrap();
        assert!(updated_file.downloaded_by.contains(&bob.id));

        // Get statistics
        let stats = storage.get_statistics().await.unwrap();
        assert_eq!(stats.user_count, 2);
        assert_eq!(stats.group_count, 1);
        assert_eq!(stats.file_count, 1);
    }

    #[tokio::test]
    async fn test_encrypted_storage_workflow() {
        let config = StorageConfig {
            backend: StorageBackend::Memory,
            encryption: EncryptionConfig {
                memory_cost: 1024,
                time_cost: 1,
                parallelism: 1,
            },
            enable_auto_backup: false, // Disable backup for tests
            ..StorageConfig::default()
        };

        let password = "secure_password";
        let salt = EncryptionService::generate_salt();

        let storage = StorageFactory::create_with_password(config, password, &salt).await.unwrap();

        // Test that encrypted storage works the same as unencrypted
        let user = create_test_user("Alice");
        storage.create_user(&user).await.unwrap();

        let retrieved_user = storage.get_user(&user.id).await.unwrap();
        assert_eq!(retrieved_user.name, user.name);
        assert_eq!(retrieved_user.id, user.id);
    }

    #[tokio::test]
    async fn test_storage_persistence() {
        // Note: This test uses in-memory database, so persistence is not actually tested
        // In a real scenario, you would use a file-based database for persistence testing
        let config = StorageConfig {
            backend: StorageBackend::SQLite,
            sqlite: SQLiteConfig {
                database_path: ":memory:".into(),
                max_connections: 1,
                enable_wal: false,
                journal_mode: "MEMORY".to_string(),
                synchronous: "OFF".to_string(),
                auto_vacuum: "NONE".to_string(),
                ..SQLiteConfig::default()
            },
            enable_auto_backup: false, // Disable backup for tests
            ..StorageConfig::default()
        };

        // Create storage and add data
        let storage = StorageFactory::create(config).await.unwrap();
        let user = create_test_user("Alice");
        storage.create_user(&user).await.unwrap();

        // Verify data exists in the same session
        let users = storage.list_users().await.unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].name, "Alice");
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        let config = StorageConfig {
            backend: StorageBackend::Memory,
            enable_auto_backup: false, // Disable backup for tests
            ..StorageConfig::default()
        };

        let storage = StorageFactory::create(config).await.unwrap();

        // Create multiple users concurrently
        let mut handles = Vec::new();

        for i in 0..10 {
            let storage_clone = match &storage {
                StorageInstance::Memory(mem_storage) => {
                    // For this test, we'll create a new storage instance
                    // In a real scenario, you'd share the same storage instance
                    let config = MemoryConfig::default();
                    let mut new_storage = MemoryStorage::new(config);
                    new_storage.initialize().await.unwrap();
                    StorageInstance::Memory(new_storage)
                }
                StorageInstance::SQLite(_) => {
                    panic!("This test is designed for memory storage");
                }
            };

            let handle = tokio::spawn(async move {
                let user = create_test_user(&format!("User{}", i));
                storage_clone.create_user(&user).await
            });

            handles.push(handle);
        }

        // Wait for all operations to complete
        for handle in handles {
            assert!(handle.await.unwrap().is_ok());
        }
    }

    #[tokio::test]
    async fn test_error_handling() {
        let config = StorageConfig {
            backend: StorageBackend::Memory,
            enable_auto_backup: false, // Disable backup for tests
            ..StorageConfig::default()
        };

        let storage = StorageFactory::create(config).await.unwrap();

        // Test various error conditions
        let non_existent_id = Uuid::new_v4();

        // User not found
        let result = storage.get_user(&non_existent_id).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StorageError::UserNotFound { .. }));

        // Group not found
        let result = storage.get_group(&non_existent_id).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StorageError::GroupNotFound { .. }));

        // File not found
        let result = storage.get_shared_file(&non_existent_id).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StorageError::FileNotFound { .. }));

        // Duplicate user creation
        let user = create_test_user("Alice");
        storage.create_user(&user).await.unwrap();

        let result = storage.create_user(&user).await;
        assert!(result.is_err());
    }
}
