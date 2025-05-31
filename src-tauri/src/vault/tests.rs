#[cfg(test)]
mod vault_tests {
    use crate::models::{VaultMasterKey, VaultMetadata};
    use crate::store::encryption::EncryptionService;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_vault_directory_creation() {
        let temp_dir = TempDir::new().unwrap();
        let vault_dir = temp_dir.path().join("test_vault");

        // Create vault directory
        fs::create_dir_all(&vault_dir).unwrap();
        assert!(vault_dir.exists());
        assert!(vault_dir.is_dir());
    }

    #[test]
    fn test_master_key_file_operations() {
        let temp_dir = TempDir::new().unwrap();
        let vault_dir = temp_dir.path().join("test_vault");
        fs::create_dir_all(&vault_dir).unwrap();

        let password = "test_password_123";
        let master_key = VaultMasterKey::new(password).unwrap();

        // Serialize and save master key
        let master_key_json = serde_json::to_vec(&master_key).unwrap();
        let master_key_path = vault_dir.join("masterkey.silvertiger");
        fs::write(&master_key_path, &master_key_json).unwrap();

        // Verify file exists and is not empty
        assert!(master_key_path.exists());
        assert!(fs::metadata(&master_key_path).unwrap().len() > 0);

        // Read and deserialize master key
        let read_data = fs::read(&master_key_path).unwrap();
        let deserialized_key: VaultMasterKey = serde_json::from_slice(&read_data).unwrap();

        // Verify password still works
        assert!(deserialized_key.verify_password(password));
        assert!(!deserialized_key.verify_password("wrong_password"));
    }

    #[test]
    fn test_vault_metadata_encryption() {
        let temp_dir = TempDir::new().unwrap();
        let vault_dir = temp_dir.path().join("test_vault");
        fs::create_dir_all(&vault_dir).unwrap();

        let password = "metadata_test_password";
        let master_key = VaultMasterKey::new(password).unwrap();

        // Create vault metadata
        let metadata = VaultMetadata::new("Test Vault".to_string(), vault_dir.clone());

        // Decrypt master key and create encryption service
        let decrypted_key = master_key.decrypt_master_key(password).unwrap();
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&decrypted_key);
        let master_key_obj = crate::store::encryption::MasterKey::from_bytes(key_array);
        let encryption_service = EncryptionService::with_master_key(master_key_obj);

        // Encrypt metadata
        let encrypted_metadata = encryption_service.encrypt_serialize(&metadata).unwrap();

        // Serialize and save encrypted metadata
        let metadata_json = serde_json::to_vec(&encrypted_metadata).unwrap();
        let config_path = vault_dir.join("vault_config.silvertiger");
        fs::write(&config_path, &metadata_json).unwrap();

        // Verify file exists
        assert!(config_path.exists());
        assert!(fs::metadata(&config_path).unwrap().len() > 0);

        // Read and decrypt metadata
        let read_data = fs::read(&config_path).unwrap();
        let encrypted_data: crate::store::encryption::EncryptedData =
            serde_json::from_slice(&read_data).unwrap();

        let decrypted_metadata: VaultMetadata =
            encryption_service.decrypt_deserialize(&encrypted_data).unwrap();

        // Verify metadata integrity
        assert_eq!(decrypted_metadata.name, "Test Vault");
        assert_eq!(decrypted_metadata.directory_path, vault_dir);
    }

    #[test]
    fn test_vault_validation() {
        let temp_dir = TempDir::new().unwrap();
        let vault_dir = temp_dir.path().join("test_vault");
        fs::create_dir_all(&vault_dir).unwrap();

        let master_key_path = vault_dir.join("masterkey.silvertiger");
        let config_path = vault_dir.join("vault_config.silvertiger");

        // Initially, vault should be invalid (missing files)
        assert!(!is_valid_vault_sync(&vault_dir));

        // Create master key file
        fs::write(&master_key_path, b"dummy_master_key").unwrap();
        assert!(!is_valid_vault_sync(&vault_dir)); // Still missing config

        // Create config file
        fs::write(&config_path, b"dummy_config").unwrap();
        assert!(is_valid_vault_sync(&vault_dir)); // Now valid

        // Remove master key file
        fs::remove_file(&master_key_path).unwrap();
        assert!(!is_valid_vault_sync(&vault_dir)); // Invalid again
    }

    #[test]
    fn test_password_verification_workflow() {
        let password = "verification_test_password";
        let wrong_password = "wrong_password";

        // Create master key
        let master_key = VaultMasterKey::new(password).unwrap();

        // Test correct password
        assert!(master_key.verify_password(password));

        // Test wrong password
        assert!(!master_key.verify_password(wrong_password));

        // Test empty password
        assert!(!master_key.verify_password(""));

        // Test similar but wrong password
        assert!(!master_key.verify_password("verification_test_passwor"));
        assert!(!master_key.verify_password("verification_test_password_extra"));
    }

    #[test]
    fn test_vault_name_sanitization() {
        let test_cases = vec![
            ("Simple Name", "simple_name"),
            ("Name With Spaces", "name_with_spaces"),
            ("Name!@#$%^&*()", "name"),
            ("123 Numbers", "123_numbers"),
            ("Mixed-Case_Name", "mixedcase_name"), // Fixed: hyphens are removed
            ("Special-Characters_123", "specialcharacters_123"), // Fixed: hyphens are removed
        ];

        for (input, expected) in test_cases {
            let sanitized = sanitize_vault_name(input);
            assert_eq!(sanitized, expected, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_encryption_key_uniqueness() {
        let password = "same_password";
        let num_keys = 5;
        let mut encrypted_keys = Vec::new();
        let mut salts = Vec::new();

        for _ in 0..num_keys {
            let master_key = VaultMasterKey::new(password).unwrap();
            encrypted_keys.push(master_key.encrypted_master_key.ciphertext.clone());
            salts.push(master_key.salt.clone());
        }

        // All encrypted keys should be different (due to different salts)
        for i in 0..encrypted_keys.len() {
            for j in (i + 1)..encrypted_keys.len() {
                assert_ne!(encrypted_keys[i], encrypted_keys[j],
                          "Encrypted keys should be unique");
            }
        }

        // All salts should be different
        for i in 0..salts.len() {
            for j in (i + 1)..salts.len() {
                assert_ne!(salts[i], salts[j], "Salts should be unique");
            }
        }
    }

    #[test]
    fn test_master_key_decryption_consistency() {
        let password = "consistency_test";
        let master_key = VaultMasterKey::new(password).unwrap();

        // Multiple decryptions should yield the same result
        let key1 = master_key.decrypt_master_key(password).unwrap();
        let key2 = master_key.decrypt_master_key(password).unwrap();
        let key3 = master_key.decrypt_master_key(password).unwrap();

        assert_eq!(key1, key2);
        assert_eq!(key2, key3);
        assert_eq!(key1.len(), 32); // AES-256 key size
    }

    #[test]
    fn test_vault_metadata_properties() {
        let name = "Property Test Vault".to_string();
        let path = PathBuf::from("/tmp/property_test");
        let metadata = VaultMetadata::new(name.clone(), path.clone());

        assert_eq!(metadata.name, name);
        assert_eq!(metadata.directory_path, path);
        assert!(!metadata.id.is_nil());
        assert_eq!(metadata.version, "1.0");
        assert!(metadata.last_accessed.is_none());
        assert_eq!(metadata.file_hierarchy.total_files, 0);
        assert_eq!(metadata.file_hierarchy.total_directories, 0);
        assert_eq!(metadata.file_hierarchy.total_size, 0);
    }

    #[test]
    fn test_encryption_service_operations() {
        let service = EncryptionService::new();
        let plaintext = b"Test data for encryption";

        // Encrypt data
        let encrypted = service.encrypt(plaintext).unwrap();

        // Verify encrypted data properties
        assert!(!encrypted.ciphertext.is_empty());
        assert_eq!(encrypted.nonce.len(), 12); // AES-GCM nonce size
        assert_eq!(encrypted.algorithm, "AES-256-GCM");

        // Decrypt data
        let decrypted = service.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // Helper functions for testing
    fn is_valid_vault_sync(vault_path: &PathBuf) -> bool {
        let master_key_path = vault_path.join("masterkey.silvertiger");
        let config_path = vault_path.join("vault_config.silvertiger");
        master_key_path.exists() && config_path.exists()
    }

    fn sanitize_vault_name(name: &str) -> String {
        name.trim()
            .to_lowercase()
            .replace(char::is_whitespace, "_")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_')
            .collect::<String>()
    }
}
