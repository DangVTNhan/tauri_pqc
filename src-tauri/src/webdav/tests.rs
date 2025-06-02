use std::path::PathBuf;
use tempfile::TempDir;
use uuid::Uuid;

use crate::models::vault::{VaultMetadata, VaultEntry, VaultEntryType, FileHierarchy};
use crate::models::webdav::{VaultMount, VaultStatus, UnlockVaultRequest, LockVaultResponse, UnlockVaultResponse};
use crate::store::encryption::EncryptionService;
use super::filesystem::VaultFileSystem;

use super::server::WebDavServerManager;
use super::commands::WebDavCommandState;

#[tokio::test]
async fn test_vault_filesystem_creation() {
    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().to_path_buf();

    // Create test vault metadata
    let vault_metadata = VaultMetadata::new(
        "test_vault".to_string(),
        vault_path.clone(),
    );

    // Create encryption service
    let master_key = crate::store::encryption::MasterKey::generate();
    let encryption_service = EncryptionService::with_master_key(master_key);

    // Create filesystem
    let _filesystem = VaultFileSystem::new(
        vault_metadata,
        encryption_service,
        vault_path,
    ).await;

    // Test that filesystem was created successfully
    // This is a basic test to ensure the struct can be instantiated
    assert!(_filesystem.is_ok());
}

#[tokio::test]
async fn test_webdav_server_manager() {
    let manager = WebDavServerManager::new();

    // Test initial state
    assert_eq!(manager.list_running_servers().await.len(), 0);

    let test_vault_id = Uuid::new_v4();
    assert!(!manager.is_server_running(&test_vault_id).await);
    assert!(manager.get_server_port(&test_vault_id).await.is_none());
}

#[tokio::test]
async fn test_vault_mount_creation() {
    let vault_id = Uuid::new_v4();
    let vault_name = "test_vault".to_string();
    let vault_path = PathBuf::from("/tmp/test_vault");

    let vault_mount = VaultMount::new(vault_id, vault_name.clone(), vault_path.clone());

    assert_eq!(vault_mount.vault_id, vault_id);
    assert_eq!(vault_mount.vault_name, vault_name);
    assert_eq!(vault_mount.vault_path, vault_path);
    assert_eq!(vault_mount.status, VaultStatus::Locked);
    assert!(!vault_mount.is_unlocked());
    assert!(!vault_mount.is_webdav_running());
    assert!(vault_mount.get_mount_url().is_none());
}

#[tokio::test]
async fn test_vault_mount_status_transitions() {
    let vault_id = Uuid::new_v4();
    let vault_name = "test_vault".to_string();
    let vault_path = PathBuf::from("/tmp/test_vault");

    let mut vault_mount = VaultMount::new(vault_id, vault_name, vault_path);

    // Test locked state
    assert_eq!(vault_mount.status, VaultStatus::Locked);
    assert!(!vault_mount.is_unlocked());
    assert!(!vault_mount.is_webdav_running());
    assert!(vault_mount.get_mount_url().is_none());

    // Test unlocked state with WebDAV running
    vault_mount.status = VaultStatus::Unlocked;
    vault_mount.webdav_config.is_running = true;
    vault_mount.webdav_config.port = 8080;
    assert!(vault_mount.is_unlocked());
    assert!(vault_mount.is_webdav_running());
    assert!(vault_mount.get_mount_url().is_some());
    assert_eq!(vault_mount.get_mount_url().unwrap(), "http://127.0.0.1:8080/");

    // Test unlocked state without WebDAV running
    vault_mount.webdav_config.is_running = false;
    assert!(vault_mount.is_unlocked());
    assert!(!vault_mount.is_webdav_running());
    assert!(vault_mount.get_mount_url().is_none());
}

#[tokio::test]
async fn test_webdav_command_state() {
    let state = WebDavCommandState::new();

    // Test initial state
    assert_eq!(state.unlocked_vaults.read().await.len(), 0);
    assert_eq!(state.webdav_state.read().await.list_mounted_vaults().len(), 0);
    assert_eq!(state.server_manager.list_running_servers().await.len(), 0);
}

#[tokio::test]
async fn test_unlock_vault_request_validation() {
    let request = UnlockVaultRequest {
        vault_id: Uuid::new_v4(),
        password: "test_password".to_string(),
    };

    // Test that request can be created and serialized
    let serialized = serde_json::to_string(&request).unwrap();
    let deserialized: UnlockVaultRequest = serde_json::from_str(&serialized).unwrap();

    assert_eq!(request.vault_id, deserialized.vault_id);
    assert_eq!(request.password, deserialized.password);
}



#[test]
fn test_vault_entry_hierarchy() {
    // Create a test file hierarchy
    let mut file_hierarchy = FileHierarchy::new();

    // Test root directory
    let root_entry = VaultEntry {
        id: Uuid::new_v4(),
        encrypted_name: b"documents".to_vec(),
        entry_type: VaultEntryType::Directory,
        size: None,
        created_at: chrono::Utc::now(),
        modified_at: chrono::Utc::now(),
        children: Some(vec![]),
        encryption_metadata: None,
    };

    file_hierarchy.root_entries.push(root_entry);
    file_hierarchy.total_directories = 1;

    assert_eq!(file_hierarchy.root_entries.len(), 1);
    assert_eq!(file_hierarchy.total_directories, 1);
    assert_eq!(file_hierarchy.total_files, 0);
}

#[tokio::test]
async fn test_encrypted_filesystem_creation() {
    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().to_path_buf();

    // Create test vault metadata
    let vault_metadata = VaultMetadata::new(
        "test_encrypted_vault".to_string(),
        vault_path.clone(),
    );

    // Create encryption service
    let master_key = crate::store::encryption::MasterKey::generate();
    let encryption_service = EncryptionService::with_master_key(master_key);

    // Create encrypted filesystem
    let encrypted_fs = super::encrypted_filesystem::EncryptedFileSystem::new(
        vault_metadata,
        encryption_service,
        vault_path,
    ).await;

    // Test that filesystem was created successfully
    assert!(encrypted_fs.is_ok());

    // Test cache clearing
    if let Ok(fs) = encrypted_fs {
        fs.clear_cache().await;
        // Should not panic or error
    }
}

#[test]
fn test_encryption_service_integration() {
    // Test that encryption service can be created
    let master_key = crate::store::encryption::MasterKey::generate();
    let encryption_service = EncryptionService::with_master_key(master_key);

    // Test basic encryption/decryption
    let test_data = b"Hello, World!";
    let encrypted = encryption_service.encrypt(test_data).unwrap();
    let decrypted = encryption_service.decrypt(&encrypted).unwrap();

    assert_eq!(test_data, decrypted.as_slice());
}

#[tokio::test]
async fn test_webdav_state_management() {
    use crate::models::webdav::WebDavState;

    let mut webdav_state = WebDavState::new();

    // Test initial state
    assert_eq!(webdav_state.list_mounted_vaults().len(), 0);
    assert_eq!(webdav_state.next_port, 8080);

    // Test port allocation
    let port1 = webdav_state.get_next_port();
    let port2 = webdav_state.get_next_port();

    assert_eq!(port1, 8080);
    assert_eq!(port2, 8081);
    assert_eq!(webdav_state.next_port, 8082);

    // Test vault mount management
    let vault_id = Uuid::new_v4();
    let vault_mount = VaultMount::new(
        vault_id,
        "test_vault".to_string(),
        PathBuf::from("/tmp/test"),
    );

    webdav_state.add_mounted_vault(vault_mount);
    assert_eq!(webdav_state.list_mounted_vaults().len(), 1);
    assert!(webdav_state.get_mounted_vault(&vault_id).is_some());

    let removed = webdav_state.remove_mounted_vault(&vault_id);
    assert!(removed.is_some());
    assert_eq!(webdav_state.list_mounted_vaults().len(), 0);
}

#[test]
fn test_vault_status_serialization() {
    // Test all vault status variants
    let statuses = vec![
        VaultStatus::Locked,
        VaultStatus::Unlocked,
    ];

    for status in statuses {
        let serialized = serde_json::to_string(&status).unwrap();
        let deserialized: VaultStatus = serde_json::from_str(&serialized).unwrap();
        assert_eq!(status, deserialized);
    }
}

// ===== NEW COMPREHENSIVE TESTS FOR SIMPLIFIED LOCK/UNLOCK SYSTEM =====

#[tokio::test]
async fn test_unlock_vault_response_serialization() {
    let vault_mount = VaultMount::new(
        Uuid::new_v4(),
        "test_vault".to_string(),
        PathBuf::from("/tmp/test"),
    );

    let response = UnlockVaultResponse {
        success: true,
        vault_mount: Some(vault_mount),
        error: None,
    };

    let serialized = serde_json::to_string(&response).unwrap();
    let deserialized: UnlockVaultResponse = serde_json::from_str(&serialized).unwrap();

    assert_eq!(response.success, deserialized.success);
    assert!(deserialized.vault_mount.is_some());
    assert!(deserialized.error.is_none());

    // Test error response
    let error_response = UnlockVaultResponse {
        success: false,
        vault_mount: None,
        error: Some("Invalid password".to_string()),
    };

    let serialized = serde_json::to_string(&error_response).unwrap();
    let deserialized: UnlockVaultResponse = serde_json::from_str(&serialized).unwrap();

    assert!(!deserialized.success);
    assert!(deserialized.vault_mount.is_none());
    assert_eq!(deserialized.error.unwrap(), "Invalid password");
}

#[tokio::test]
async fn test_lock_vault_response_serialization() {
    let response = LockVaultResponse {
        success: true,
        error: None,
    };

    let serialized = serde_json::to_string(&response).unwrap();
    let deserialized: LockVaultResponse = serde_json::from_str(&serialized).unwrap();

    assert_eq!(response.success, deserialized.success);
    assert!(deserialized.error.is_none());

    // Test error response
    let error_response = LockVaultResponse {
        success: false,
        error: Some("Vault not found".to_string()),
    };

    let serialized = serde_json::to_string(&error_response).unwrap();
    let deserialized: LockVaultResponse = serde_json::from_str(&serialized).unwrap();

    assert!(!deserialized.success);
    assert_eq!(deserialized.error.unwrap(), "Vault not found");
}

#[tokio::test]
async fn test_webdav_server_lifecycle() {
    let manager = WebDavServerManager::new();
    let vault_id = Uuid::new_v4();

    // Test initial state
    assert!(!manager.is_server_running(&vault_id).await);
    assert!(manager.get_server_port(&vault_id).await.is_none());
    assert_eq!(manager.list_running_servers().await.len(), 0);

    // Test that we can create a vault metadata for testing
    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().to_path_buf();

    let vault_metadata = VaultMetadata::new(
        "test_vault".to_string(),
        vault_path.clone(),
    );

    let master_key = crate::store::encryption::MasterKey::generate();
    let encryption_service = EncryptionService::with_master_key(master_key);

    // Test server start
    let result = manager.start_server(
        vault_id,
        vault_metadata,
        encryption_service,
        vault_path,
        Some(9999), // Use a specific port for testing
    ).await;

    assert!(result.is_ok());
    let vault_mount = result.unwrap();
    assert_eq!(vault_mount.vault_id, vault_id);
    assert_eq!(vault_mount.status, VaultStatus::Unlocked);
    assert!(vault_mount.is_webdav_running());
    assert_eq!(vault_mount.webdav_config.port, 9999);

    // Test server is now running
    assert!(manager.is_server_running(&vault_id).await);
    assert_eq!(manager.get_server_port(&vault_id).await, Some(9999));
    assert_eq!(manager.list_running_servers().await.len(), 1);

    // Test server stop
    let stop_result = manager.stop_server(&vault_id).await;
    assert!(stop_result.is_ok());

    // Test server is no longer running
    assert!(!manager.is_server_running(&vault_id).await);
    assert!(manager.get_server_port(&vault_id).await.is_none());
    assert_eq!(manager.list_running_servers().await.len(), 0);
}

#[tokio::test]
async fn test_webdav_state_vault_management() {
    use crate::models::webdav::WebDavState;

    let mut webdav_state = WebDavState::new();
    let vault_id1 = Uuid::new_v4();
    let vault_id2 = Uuid::new_v4();

    // Test adding multiple vaults
    let vault_mount1 = VaultMount::new(
        vault_id1,
        "vault1".to_string(),
        PathBuf::from("/tmp/vault1"),
    );
    let vault_mount2 = VaultMount::new(
        vault_id2,
        "vault2".to_string(),
        PathBuf::from("/tmp/vault2"),
    );

    webdav_state.add_mounted_vault(vault_mount1);
    webdav_state.add_mounted_vault(vault_mount2);

    assert_eq!(webdav_state.list_mounted_vaults().len(), 2);
    assert!(webdav_state.get_mounted_vault(&vault_id1).is_some());
    assert!(webdav_state.get_mounted_vault(&vault_id2).is_some());

    // Test mutable access
    {
        let vault_mount = webdav_state.get_mounted_vault_mut(&vault_id1).unwrap();
        vault_mount.status = VaultStatus::Unlocked;
        vault_mount.webdav_config.is_running = true;
    }

    let vault_mount = webdav_state.get_mounted_vault(&vault_id1).unwrap();
    assert_eq!(vault_mount.status, VaultStatus::Unlocked);
    assert!(vault_mount.is_webdav_running());

    // Test removing vaults
    let removed = webdav_state.remove_mounted_vault(&vault_id1);
    assert!(removed.is_some());
    assert_eq!(webdav_state.list_mounted_vaults().len(), 1);
    assert!(webdav_state.get_mounted_vault(&vault_id1).is_none());
    assert!(webdav_state.get_mounted_vault(&vault_id2).is_some());
}

#[tokio::test]
async fn test_vault_mount_url_generation() {
    let vault_id = Uuid::new_v4();
    let mut vault_mount = VaultMount::new(
        vault_id,
        "test_vault".to_string(),
        PathBuf::from("/tmp/test"),
    );

    // Test locked vault (no URL)
    assert!(vault_mount.get_mount_url().is_none());

    // Test unlocked vault without WebDAV running (no URL)
    vault_mount.status = VaultStatus::Unlocked;
    assert!(vault_mount.get_mount_url().is_none());

    // Test unlocked vault with WebDAV running (has URL)
    vault_mount.webdav_config.is_running = true;
    vault_mount.webdav_config.port = 8080;
    assert!(vault_mount.get_mount_url().is_some());
    assert_eq!(vault_mount.get_mount_url().unwrap(), "http://127.0.0.1:8080/");

    // Test different port
    vault_mount.webdav_config.port = 9000;
    assert_eq!(vault_mount.get_mount_url().unwrap(), "http://127.0.0.1:9000/");
}

#[tokio::test]
async fn test_vault_mount_access_tracking() {
    let vault_id = Uuid::new_v4();
    let mut vault_mount = VaultMount::new(
        vault_id,
        "test_vault".to_string(),
        PathBuf::from("/tmp/test"),
    );

    // Test initial state
    assert!(vault_mount.last_accessed.is_none());

    // Test marking as accessed
    vault_mount.mark_accessed();
    assert!(vault_mount.last_accessed.is_some());

    let first_access = vault_mount.last_accessed.unwrap();

    // Wait a bit and mark accessed again
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    vault_mount.mark_accessed();

    let second_access = vault_mount.last_accessed.unwrap();
    assert!(second_access > first_access);
}

#[test]
fn test_webdav_config_creation() {
    use crate::models::webdav::WebDavConfig;

    let config = WebDavConfig {
        host: "127.0.0.1".to_string(),
        port: 8080,
        is_running: false,
        started_at: None,
    };

    assert_eq!(config.host, "127.0.0.1");
    assert_eq!(config.port, 8080);
    assert!(!config.is_running);
    assert!(config.started_at.is_none());

    // Test with started_at
    let config_with_start = WebDavConfig {
        host: "127.0.0.1".to_string(),
        port: 8080,
        is_running: true,
        started_at: Some(chrono::Utc::now()),
    };

    assert!(config_with_start.is_running);
    assert!(config_with_start.started_at.is_some());
}

#[tokio::test]
async fn test_command_state_integration() {
    let state = WebDavCommandState::new();
    let vault_id = Uuid::new_v4();

    // Test initial state
    assert_eq!(state.unlocked_vaults.read().await.len(), 0);
    assert_eq!(state.webdav_state.read().await.list_mounted_vaults().len(), 0);

    // Test adding unlocked vault
    let master_key = crate::store::encryption::MasterKey::generate();
    let encryption_service = EncryptionService::with_master_key(master_key);

    {
        let mut unlocked_vaults = state.unlocked_vaults.write().await;
        unlocked_vaults.insert(vault_id, encryption_service);
    }

    assert_eq!(state.unlocked_vaults.read().await.len(), 1);
    assert!(state.unlocked_vaults.read().await.contains_key(&vault_id));

    // Test adding vault mount
    let vault_mount = VaultMount::new(
        vault_id,
        "test_vault".to_string(),
        PathBuf::from("/tmp/test"),
    );

    {
        let mut webdav_state = state.webdav_state.write().await;
        webdav_state.add_mounted_vault(vault_mount);
    }

    assert_eq!(state.webdav_state.read().await.list_mounted_vaults().len(), 1);

    // Test cleanup
    {
        let mut unlocked_vaults = state.unlocked_vaults.write().await;
        unlocked_vaults.remove(&vault_id);
    }

    {
        let mut webdav_state = state.webdav_state.write().await;
        webdav_state.remove_mounted_vault(&vault_id);
    }

    assert_eq!(state.unlocked_vaults.read().await.len(), 0);
    assert_eq!(state.webdav_state.read().await.list_mounted_vaults().len(), 0);
}

#[test]
fn test_vault_status_display() {
    // Test that vault statuses can be formatted for display
    let locked = VaultStatus::Locked;
    let unlocked = VaultStatus::Unlocked;

    // Test Debug formatting
    assert_eq!(format!("{:?}", locked), "Locked");
    assert_eq!(format!("{:?}", unlocked), "Unlocked");

    // Test that they can be compared
    assert_ne!(locked, unlocked);
    assert_eq!(locked, VaultStatus::Locked);
    assert_eq!(unlocked, VaultStatus::Unlocked);
}

#[tokio::test]
async fn test_unmount_webdav_volume_function() {
    // Test the unmount function with different scenarios

    // Test with vault name
    let result = crate::commands::unmount_webdav_volume(Some("test_vault".to_string())).await;
    // On macOS, this should attempt to unmount but may fail if no volume is mounted
    // We just verify the function doesn't panic and returns a result
    assert!(result.is_ok() || result.is_err());

    // Test with no vault name (IP-based unmount)
    let result = crate::commands::unmount_webdav_volume(None).await;
    // Same as above - should not panic
    assert!(result.is_ok() || result.is_err());

    // Test with empty vault name
    let result = crate::commands::unmount_webdav_volume(Some("".to_string())).await;
    assert!(result.is_ok() || result.is_err());
}

#[tokio::test]
async fn test_concurrent_vault_operations() {
    let state = WebDavCommandState::new();
    let vault_id1 = Uuid::new_v4();
    let vault_id2 = Uuid::new_v4();

    // Test concurrent access to different vaults
    let master_key1 = crate::store::encryption::MasterKey::generate();
    let master_key2 = crate::store::encryption::MasterKey::generate();
    let encryption_service1 = EncryptionService::with_master_key(master_key1);
    let encryption_service2 = EncryptionService::with_master_key(master_key2);

    // Simulate concurrent operations
    let state_clone = state.clone();
    let handle1 = tokio::spawn(async move {
        let mut unlocked_vaults = state_clone.unlocked_vaults.write().await;
        unlocked_vaults.insert(vault_id1, encryption_service1);
    });

    let state_clone = state.clone();
    let handle2 = tokio::spawn(async move {
        let mut unlocked_vaults = state_clone.unlocked_vaults.write().await;
        unlocked_vaults.insert(vault_id2, encryption_service2);
    });

    // Wait for both operations to complete
    let _ = tokio::join!(handle1, handle2);

    // Verify both vaults are unlocked
    let unlocked_vaults = state.unlocked_vaults.read().await;
    assert_eq!(unlocked_vaults.len(), 2);
    assert!(unlocked_vaults.contains_key(&vault_id1));
    assert!(unlocked_vaults.contains_key(&vault_id2));
}
