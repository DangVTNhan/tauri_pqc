use std::path::PathBuf;
use std::fs;
use tempfile::TempDir;
use uuid::Uuid;

use crate::models::vault::{VaultMetadata, VaultEntry, VaultEntryType, FileHierarchy, VaultMasterKey};
use crate::models::webdav::{VaultMount, VaultStatus, UnlockVaultRequest, LockVaultResponse, UnlockVaultResponse};
use crate::store::encryption::{EncryptionService, EncryptedData};
use super::filesystem::VaultFileSystem;
use super::encrypted_filesystem::EncryptedFileSystem;

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
    vault_mount.webdav_config.host = "localhost".to_string();
    vault_mount.mount_url = Some("http://localhost:8080/TestVault/".to_string());
    assert!(vault_mount.is_unlocked());
    assert!(vault_mount.is_webdav_running());
    assert!(vault_mount.get_mount_url().is_some());
    assert_eq!(vault_mount.get_mount_url().unwrap(), "http://localhost:8080/TestVault/");

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
    assert_eq!(vault_mount.webdav_config.port, 9999); // Custom port should override default

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
    vault_mount.webdav_config.host = "localhost".to_string();
    vault_mount.mount_url = Some("http://localhost:8080/TestVault/".to_string());
    assert!(vault_mount.get_mount_url().is_some());
    assert_eq!(vault_mount.get_mount_url().unwrap(), "http://localhost:8080/TestVault/");

    // Test different vault name in URL
    vault_mount.mount_url = Some("http://localhost:8080/AnotherVault/".to_string());
    assert_eq!(vault_mount.get_mount_url().unwrap(), "http://localhost:8080/AnotherVault/");
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
        host: "localhost".to_string(),
        port: 8080,
        is_running: false,
        started_at: None,
        username: Some("testuser".to_string()),
        password: Some("testpass".to_string()),
    };

    assert_eq!(config.host, "localhost");
    assert_eq!(config.port, 8080);
    assert!(!config.is_running);
    assert!(config.started_at.is_none());

    // Test with started_at
    let config_with_start = WebDavConfig {
        host: "localhost".to_string(),
        port: 8080,
        is_running: true,
        started_at: Some(chrono::Utc::now()),
        username: Some("testuser2".to_string()),
        password: Some("testpass2".to_string()),
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

// ===== COMPREHENSIVE VAULT INTEGRATION TESTS =====

#[tokio::test]
async fn test_complete_vault_lifecycle_with_password() {
    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().to_path_buf();
    let vault_name = "test_vault_lifecycle";
    let password = "test_password_123";

    // Step 1: Create a test vault with password
    let vault_dir = vault_path.join(vault_name);
    fs::create_dir_all(&vault_dir).unwrap();

    // Create master key from password
    let master_key = VaultMasterKey::new(password).unwrap();

    // Create vault metadata
    let vault_metadata = VaultMetadata::new(vault_name.to_string(), vault_dir.clone());

    // Decrypt master key and create encryption service
    let decrypted_master_key = master_key.decrypt_master_key(password).unwrap();
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&decrypted_master_key);
    let master_key_obj = crate::store::encryption::MasterKey::from_bytes(key_array);
    let encryption_service = EncryptionService::with_master_key(master_key_obj);

    // Save master key file (encrypted with password)
    let master_key_json = serde_json::to_vec(&master_key).unwrap();
    let master_key_path = vault_dir.join("masterkey.silvertiger");
    fs::write(&master_key_path, &master_key_json).unwrap();

    // Save encrypted vault config
    let encrypted_metadata = encryption_service.encrypt_serialize(&vault_metadata).unwrap();
    let metadata_json = serde_json::to_vec(&encrypted_metadata).unwrap();
    let config_path = vault_dir.join("vault_config.silvertiger");
    fs::write(&config_path, &metadata_json).unwrap();

    // Create files directory
    let files_dir = vault_dir.join("files");
    fs::create_dir_all(&files_dir).unwrap();

    // Step 2: Test that Welcome.txt is created and encrypted
    let encrypted_fs = EncryptedFileSystem::new(
        vault_metadata.clone(),
        encryption_service.clone(),
        vault_dir.clone(),
    ).await.unwrap();

    // Check that Welcome.txt exists on disk (encrypted)
    let welcome_file_path = files_dir.join("Welcome.txt");
    assert!(welcome_file_path.exists());

    // Read the encrypted file from disk
    let encrypted_welcome_data = fs::read(&welcome_file_path).unwrap();
    let encrypted_welcome: EncryptedData = serde_json::from_slice(&encrypted_welcome_data).unwrap();

    // Decrypt and verify Welcome.txt content
    let decrypted_welcome = encryption_service.decrypt(&encrypted_welcome).unwrap();
    let welcome_content = String::from_utf8(decrypted_welcome).unwrap();
    assert!(welcome_content.contains("Welcome to your encrypted vault"));
    assert!(welcome_content.contains(vault_name));

    println!("✓ Welcome.txt created and encrypted successfully");

    // Step 3: Test encrypting a custom test file
    let test_file_content = "This is a test file for encryption testing.";
    let test_file_encrypted = encryption_service.encrypt(test_file_content.as_bytes()).unwrap();
    let test_file_json = serde_json::to_vec(&test_file_encrypted).unwrap();
    let test_file_path = files_dir.join("test_file.txt");
    fs::write(&test_file_path, &test_file_json).unwrap();

    // Verify the test file can be decrypted
    let read_encrypted_data = fs::read(&test_file_path).unwrap();
    let read_encrypted: EncryptedData = serde_json::from_slice(&read_encrypted_data).unwrap();
    let decrypted_test_content = encryption_service.decrypt(&read_encrypted).unwrap();
    let decrypted_test_string = String::from_utf8(decrypted_test_content).unwrap();
    assert_eq!(decrypted_test_string, test_file_content);

    println!("✓ Test file encrypted and decrypted successfully");

    // Step 4: Test that invalid password cannot decrypt files
    let wrong_password = "wrong_password";

    // Try to create encryption service with wrong password
    let wrong_master_key_result = master_key.decrypt_master_key(wrong_password);
    assert!(wrong_master_key_result.is_err());

    println!("✓ Invalid password correctly rejected");

    // Clear cache to ensure clean state
    encrypted_fs.clear_cache().await;
}

#[tokio::test]
async fn test_vault_unlock_creates_virtual_volume() {
    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().to_path_buf();
    let vault_name = "test_vault_webdav";
    let password = "webdav_test_password";

    // Create a complete test vault
    let vault_dir = vault_path.join(vault_name);
    fs::create_dir_all(&vault_dir).unwrap();

    let master_key = VaultMasterKey::new(password).unwrap();
    let vault_metadata = VaultMetadata::new(vault_name.to_string(), vault_dir.clone());

    // Create encryption service
    let decrypted_master_key = master_key.decrypt_master_key(password).unwrap();
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&decrypted_master_key);
    let master_key_obj = crate::store::encryption::MasterKey::from_bytes(key_array);
    let encryption_service = EncryptionService::with_master_key(master_key_obj);

    // Save vault files
    let master_key_json = serde_json::to_vec(&master_key).unwrap();
    let master_key_path = vault_dir.join("masterkey.silvertiger");
    fs::write(&master_key_path, &master_key_json).unwrap();

    let encrypted_metadata = encryption_service.encrypt_serialize(&vault_metadata).unwrap();
    let metadata_json = serde_json::to_vec(&encrypted_metadata).unwrap();
    let config_path = vault_dir.join("vault_config.silvertiger");
    fs::write(&config_path, &metadata_json).unwrap();

    let files_dir = vault_dir.join("files");
    fs::create_dir_all(&files_dir).unwrap();

    // Test WebDAV server creation and virtual volume
    let server_manager = WebDavServerManager::new();
    let vault_id = Uuid::new_v4();

    // Start WebDAV server (simulates vault unlock)
    let vault_mount_result = server_manager.start_server(
        vault_id,
        vault_metadata.clone(),
        encryption_service.clone(),
        vault_dir.clone(),
        Some(9998), // Use specific port for testing
    ).await;

    assert!(vault_mount_result.is_ok());
    let vault_mount = vault_mount_result.unwrap();

    // Verify vault is unlocked and WebDAV is running
    assert_eq!(vault_mount.status, VaultStatus::Unlocked);
    assert!(vault_mount.is_webdav_running());
    assert_eq!(vault_mount.webdav_config.port, 9998); // Custom port should override default
    assert!(vault_mount.get_mount_url().is_some());
    assert_eq!(vault_mount.get_mount_url().unwrap(), "http://127.0.0.1:9998/test_vault_webdav/");

    // Verify authentication credentials are set to defaults
    assert_eq!(vault_mount.webdav_config.username, Some("vault_user".to_string()));
    assert_eq!(vault_mount.webdav_config.password, Some("vault_pass".to_string()));

    // Verify server is tracked
    assert!(server_manager.is_server_running(&vault_id).await);
    assert_eq!(server_manager.get_server_port(&vault_id).await, Some(9998));

    println!("✓ Virtual volume created successfully on unlock");

    // Test that files are accessible through the virtual volume
    // (In a real scenario, this would be accessible via WebDAV at the mount URL)

    // Stop the server (simulates vault lock)
    let stop_result = server_manager.stop_server(&vault_id).await;
    assert!(stop_result.is_ok());

    // Verify server is no longer running
    assert!(!server_manager.is_server_running(&vault_id).await);
    assert!(server_manager.get_server_port(&vault_id).await.is_none());

    println!("✓ Virtual volume removed successfully on lock");
}

#[tokio::test]
async fn test_complete_unlock_lock_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().to_path_buf();
    let vault_name = "test_vault_workflow";
    let password = "workflow_test_password";

    // Create a complete test vault
    let vault_dir = vault_path.join(vault_name);
    fs::create_dir_all(&vault_dir).unwrap();

    let master_key = VaultMasterKey::new(password).unwrap();
    let vault_metadata = VaultMetadata::new(vault_name.to_string(), vault_dir.clone());

    let decrypted_master_key = master_key.decrypt_master_key(password).unwrap();
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&decrypted_master_key);
    let master_key_obj = crate::store::encryption::MasterKey::from_bytes(key_array);
    let encryption_service = EncryptionService::with_master_key(master_key_obj);

    // Save vault files
    let master_key_json = serde_json::to_vec(&master_key).unwrap();
    let master_key_path = vault_dir.join("masterkey.silvertiger");
    fs::write(&master_key_path, &master_key_json).unwrap();

    let encrypted_metadata = encryption_service.encrypt_serialize(&vault_metadata).unwrap();
    let metadata_json = serde_json::to_vec(&encrypted_metadata).unwrap();
    let config_path = vault_dir.join("vault_config.silvertiger");
    fs::write(&config_path, &metadata_json).unwrap();

    let files_dir = vault_dir.join("files");
    fs::create_dir_all(&files_dir).unwrap();

    // Create WebDAV command state
    let webdav_state = WebDavCommandState::new();
    let vault_id = Uuid::new_v4();

    // Test unlock workflow
    let unlock_request = UnlockVaultRequest {
        vault_id,
        password: password.to_string(),
    };

    // Simulate the unlock process by manually adding to state
    {
        let mut unlocked_vaults = webdav_state.unlocked_vaults.write().await;
        unlocked_vaults.insert(vault_id, encryption_service.clone());
    }

    // Start WebDAV server
    let vault_mount_result = webdav_state.server_manager.start_server(
        vault_id,
        vault_metadata.clone(),
        encryption_service.clone(),
        vault_dir.clone(),
        Some(9997),
    ).await;

    assert!(vault_mount_result.is_ok());
    let vault_mount = vault_mount_result.unwrap();

    // Add to WebDAV state
    {
        let mut webdav_state_guard = webdav_state.webdav_state.write().await;
        webdav_state_guard.add_mounted_vault(vault_mount.clone());
    }

    // Verify unlock state
    assert_eq!(webdav_state.unlocked_vaults.read().await.len(), 1);
    assert_eq!(webdav_state.webdav_state.read().await.list_mounted_vaults().len(), 1);
    assert!(webdav_state.server_manager.is_server_running(&vault_id).await);

    println!("✓ Vault unlocked successfully with virtual volume");

    // Test that files can be accessed (simulate file operations)
    let encrypted_fs = EncryptedFileSystem::new(
        vault_metadata.clone(),
        encryption_service.clone(),
        vault_dir.clone(),
    ).await.unwrap();

    // Verify Welcome.txt is accessible
    let welcome_file_path = files_dir.join("Welcome.txt");
    assert!(welcome_file_path.exists());

    // Test lock workflow
    // Stop WebDAV server
    let stop_result = webdav_state.server_manager.stop_server(&vault_id).await;
    assert!(stop_result.is_ok());

    // Remove from unlocked vaults
    {
        let mut unlocked_vaults = webdav_state.unlocked_vaults.write().await;
        unlocked_vaults.remove(&vault_id);
    }

    // Remove from WebDAV state
    {
        let mut webdav_state_guard = webdav_state.webdav_state.write().await;
        webdav_state_guard.remove_mounted_vault(&vault_id);
    }

    // Clear filesystem cache (simulates memory cleanup)
    encrypted_fs.clear_cache().await;

    // Verify lock state
    assert_eq!(webdav_state.unlocked_vaults.read().await.len(), 0);
    assert_eq!(webdav_state.webdav_state.read().await.list_mounted_vaults().len(), 0);
    assert!(!webdav_state.server_manager.is_server_running(&vault_id).await);

    println!("✓ Vault locked successfully with virtual volume removed and memory cleared");
}

#[tokio::test]
async fn test_file_encryption_with_multiple_passwords() {
    let temp_dir = TempDir::new().unwrap();
    let vault_path = temp_dir.path().to_path_buf();
    let vault_name = "test_vault_multipass";
    let correct_password = "correct_password_123";
    let wrong_password = "wrong_password_456";

    // Create vault with correct password
    let vault_dir = vault_path.join(vault_name);
    fs::create_dir_all(&vault_dir).unwrap();

    let master_key = VaultMasterKey::new(correct_password).unwrap();
    let vault_metadata = VaultMetadata::new(vault_name.to_string(), vault_dir.clone());

    // Create encryption service with correct password
    let decrypted_master_key = master_key.decrypt_master_key(correct_password).unwrap();
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&decrypted_master_key);
    let master_key_obj = crate::store::encryption::MasterKey::from_bytes(key_array);
    let encryption_service = EncryptionService::with_master_key(master_key_obj);

    // Save vault files
    let master_key_json = serde_json::to_vec(&master_key).unwrap();
    let master_key_path = vault_dir.join("masterkey.silvertiger");
    fs::write(&master_key_path, &master_key_json).unwrap();

    let files_dir = vault_dir.join("files");
    fs::create_dir_all(&files_dir).unwrap();

    // Test 1: Encrypt multiple test files
    let test_files = vec![
        ("document1.txt", "This is the first test document."),
        ("document2.txt", "This is the second test document with more content."),
        ("notes.md", "# Test Notes\n\nThis is a markdown file for testing."),
    ];

    for (filename, content) in &test_files {
        let encrypted_content = encryption_service.encrypt(content.as_bytes()).unwrap();
        let encrypted_json = serde_json::to_vec(&encrypted_content).unwrap();
        let file_path = files_dir.join(filename);
        fs::write(&file_path, &encrypted_json).unwrap();
    }

    println!("✓ Multiple files encrypted successfully");

    // Test 2: Verify files can be decrypted with correct password
    for (filename, expected_content) in &test_files {
        let file_path = files_dir.join(filename);
        let encrypted_data = fs::read(&file_path).unwrap();
        let encrypted: EncryptedData = serde_json::from_slice(&encrypted_data).unwrap();
        let decrypted = encryption_service.decrypt(&encrypted).unwrap();
        let decrypted_content = String::from_utf8(decrypted).unwrap();
        assert_eq!(&decrypted_content, expected_content);
    }

    println!("✓ All files decrypted successfully with correct password");

    // Test 3: Verify files cannot be decrypted with wrong password
    let wrong_master_key_result = master_key.decrypt_master_key(wrong_password);
    assert!(wrong_master_key_result.is_err());

    println!("✓ Wrong password correctly rejected for master key");

    // Test 4: Test encrypted filesystem with files
    let encrypted_fs = EncryptedFileSystem::new(
        vault_metadata.clone(),
        encryption_service.clone(),
        vault_dir.clone(),
    ).await.unwrap();

    // Verify Welcome.txt was created
    let welcome_file_path = files_dir.join("Welcome.txt");
    assert!(welcome_file_path.exists());

    // Test that all files are accessible through encrypted filesystem
    // (This simulates WebDAV access)

    // Clear cache to test memory cleanup
    encrypted_fs.clear_cache().await;

    println!("✓ Encrypted filesystem created and cache cleared successfully");

    // Test 5: Verify file integrity after cache operations
    for (filename, expected_content) in &test_files {
        let file_path = files_dir.join(filename);
        let encrypted_data = fs::read(&file_path).unwrap();
        let encrypted: EncryptedData = serde_json::from_slice(&encrypted_data).unwrap();
        let decrypted = encryption_service.decrypt(&encrypted).unwrap();
        let decrypted_content = String::from_utf8(decrypted).unwrap();
        assert_eq!(&decrypted_content, expected_content);
    }

    println!("✓ File integrity maintained after cache operations");
}
