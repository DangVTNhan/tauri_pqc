#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use crate::store::auth::AuthStorage;

    /// Test key generation and storage consistency
    #[tokio::test]
    async fn test_key_generation_and_storage_consistency() {
        println!("🧪 Testing key generation and storage consistency");

        // Setup temporary directory for test database
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test_keys.db");

        // Initialize auth storage with persistence
        let auth_storage = AuthStorage::with_sqlite_persistence(db_path, "test_master_password")
            .await
            .expect("Failed to initialize auth storage");

        let username = "test_user";
        let password = "test_password_123";

        // Generate key bundle for the user
        let key_bundle_result = crate::commands::generate_key_bundle(password.to_string()).await
            .expect("Failed to generate key bundle");

        // Register user with keys
        let user_result = auth_storage.register_user_with_keys(
            username.to_string(),
            password.to_string(),
            key_bundle_result.private_keys
        ).await;
        assert!(user_result.is_ok(), "Failed to register user: {:?}", user_result.err());
        let user = user_result.unwrap();

        // Get private keys multiple times and verify consistency
        let keys1_result = auth_storage.get_user_private_keys(&user.id, password).await;
        assert!(keys1_result.is_ok(), "Failed to get private keys (1st time): {:?}", keys1_result.err());
        let keys1 = keys1_result.unwrap();

        let keys2_result = auth_storage.get_user_private_keys(&user.id, password).await;
        assert!(keys2_result.is_ok(), "Failed to get private keys (2nd time): {:?}", keys2_result.err());
        let keys2 = keys2_result.unwrap();

        let keys3_result = auth_storage.get_user_private_keys(&user.id, password).await;
        assert!(keys3_result.is_ok(), "Failed to get private keys (3rd time): {:?}", keys3_result.err());
        let keys3 = keys3_result.unwrap();

        // Verify all keys are identical
        assert_eq!(keys1.signed_pre_key, keys2.signed_pre_key, "Signed pre-key should be consistent");
        assert_eq!(keys1.signed_pre_key, keys3.signed_pre_key, "Signed pre-key should be consistent");
        assert_eq!(keys1.kyber_pre_key, keys2.kyber_pre_key, "Kyber pre-key should be consistent");
        assert_eq!(keys1.kyber_pre_key, keys3.kyber_pre_key, "Kyber pre-key should be consistent");
        assert_eq!(keys1.identity_key, keys2.identity_key, "Identity key should be consistent");
        assert_eq!(keys1.identity_key, keys3.identity_key, "Identity key should be consistent");

        println!("✅ Key consistency test passed");
    }

    /// Test logout and re-login key persistence
    #[tokio::test]
    async fn test_logout_login_key_persistence() {
        println!("🧪 Testing logout/login key persistence");

        // Setup temporary directory for test database
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test_persistence.db");

        // Initialize auth storage
        let auth_storage = AuthStorage::with_sqlite_persistence(db_path.clone(), "test_master_password")
            .await
            .expect("Failed to initialize auth storage");

        let username = "persistence_user";
        let password = "persistence_password_123";

        // Generate key bundle for the user
        let key_bundle_result = crate::commands::generate_key_bundle(password.to_string()).await
            .expect("Failed to generate key bundle");

        // Register user with keys
        let user_result = auth_storage.register_user_with_keys(
            username.to_string(),
            password.to_string(),
            key_bundle_result.private_keys
        ).await;
        assert!(user_result.is_ok(), "Failed to register user");
        let user = user_result.unwrap();

        // Get keys before logout
        let keys_before_logout_result = auth_storage.get_user_private_keys(&user.id, password).await;
        assert!(keys_before_logout_result.is_ok(), "Failed to get keys before logout");
        let keys_before_logout = keys_before_logout_result.unwrap();

        // Simulate logout by creating a new auth storage instance (simulates app restart)
        let auth_storage2 = AuthStorage::with_sqlite_persistence(db_path, "test_master_password")
            .await
            .expect("Failed to initialize auth storage after restart");

        // Get keys after "restart"
        let keys_after_restart_result = auth_storage2.get_user_private_keys(&user.id, password).await;
        assert!(keys_after_restart_result.is_ok(), "Failed to get keys after restart");
        let keys_after_restart = keys_after_restart_result.unwrap();

        // Verify keys are identical after restart
        assert_eq!(
            keys_before_logout.signed_pre_key,
            keys_after_restart.signed_pre_key,
            "Signed pre-key should persist across restart"
        );
        assert_eq!(
            keys_before_logout.kyber_pre_key,
            keys_after_restart.kyber_pre_key,
            "Kyber pre-key should persist across restart"
        );
        assert_eq!(
            keys_before_logout.identity_key,
            keys_after_restart.identity_key,
            "Identity key should persist across restart"
        );

        println!("✅ Logout/login key persistence test passed");
    }

    /// Test multiple users with separate key storage
    #[tokio::test]
    async fn test_multiple_users_separate_keys() {
        println!("🧪 Testing multiple users with separate key storage");

        // Setup temporary directory for test database
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test_multi_users.db");

        // Initialize auth storage
        let auth_storage = AuthStorage::with_sqlite_persistence(db_path, "test_master_password")
            .await
            .expect("Failed to initialize auth storage");

        // Generate key bundles for both users
        let user1_key_bundle = crate::commands::generate_key_bundle("alice_password".to_string()).await
            .expect("Failed to generate key bundle for user 1");
        let user2_key_bundle = crate::commands::generate_key_bundle("bob_password".to_string()).await
            .expect("Failed to generate key bundle for user 2");

        // Register two users with keys
        let user1_result = auth_storage.register_user_with_keys(
            "alice".to_string(),
            "alice_password".to_string(),
            user1_key_bundle.private_keys
        ).await;
        assert!(user1_result.is_ok(), "Failed to register user 1");
        let user1 = user1_result.unwrap();

        let user2_result = auth_storage.register_user_with_keys(
            "bob".to_string(),
            "bob_password".to_string(),
            user2_key_bundle.private_keys
        ).await;
        assert!(user2_result.is_ok(), "Failed to register user 2");
        let user2 = user2_result.unwrap();

        // Get keys for both users
        let user1_keys_result = auth_storage.get_user_private_keys(&user1.id, "alice_password").await;
        assert!(user1_keys_result.is_ok(), "Failed to get user 1 keys");
        let user1_keys = user1_keys_result.unwrap();

        let user2_keys_result = auth_storage.get_user_private_keys(&user2.id, "bob_password").await;
        assert!(user2_keys_result.is_ok(), "Failed to get user 2 keys");
        let user2_keys = user2_keys_result.unwrap();

        // Verify keys are different between users
        assert_ne!(
            user1_keys.signed_pre_key,
            user2_keys.signed_pre_key,
            "Users should have different signed pre-keys"
        );
        assert_ne!(
            user1_keys.kyber_pre_key,
            user2_keys.kyber_pre_key,
            "Users should have different Kyber pre-keys"
        );
        assert_ne!(
            user1_keys.identity_key,
            user2_keys.identity_key,
            "Users should have different identity keys"
        );

        println!("✅ Multiple users separate keys test passed");
    }

    #[tokio::test]
    async fn test_salt_persistence_across_restarts() -> Result<(), Box<dyn std::error::Error>> {
        use tempfile::TempDir;
        use crate::store::auth::AuthStorage;

        // Setup temporary directory for test database
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test_salt_persistence.db");
        let salt_path = db_path.with_extension("salt");

        // First initialization - should create salt file
        {
            let auth_storage1 = AuthStorage::with_sqlite_persistence(db_path.clone(), "test_master_password")
                .await
                .expect("Failed to initialize auth storage first time");

            // Verify salt file was created
            assert!(salt_path.exists(), "Salt file should be created");

            // Register a user
            let username = "salt_test_user";
            let password = "salt_test_password_123";

            let key_bundle_result = crate::commands::generate_key_bundle(password.to_string()).await
                .expect("Failed to generate key bundle");

            let user_result = auth_storage1.register_user_with_keys(
                username.to_string(),
                password.to_string(),
                key_bundle_result.private_keys
            ).await;
            assert!(user_result.is_ok(), "Failed to register user");
        }

        // Read the salt file content
        let original_salt = tokio::fs::read(&salt_path).await
            .expect("Failed to read salt file");

        // Second initialization - should reuse existing salt
        {
            let auth_storage2 = AuthStorage::with_sqlite_persistence(db_path.clone(), "test_master_password")
                .await
                .expect("Failed to initialize auth storage second time");

            // Verify salt file still exists and has same content
            assert!(salt_path.exists(), "Salt file should still exist");
            let reused_salt = tokio::fs::read(&salt_path).await
                .expect("Failed to read salt file second time");

            assert_eq!(original_salt, reused_salt, "Salt should be identical across restarts");

            // Should be able to authenticate existing user
            let auth_result = auth_storage2.authenticate_user("salt_test_user".to_string(), "salt_test_password_123".to_string()).await;
            assert!(auth_result.is_ok(), "Should be able to authenticate with reused salt: {:?}", auth_result.err());
        }

        println!("✅ Salt persistence test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_register_login_logout_new_account_scenario() -> Result<(), Box<dyn std::error::Error>> {
        use tempfile::TempDir;
        use crate::store::auth::AuthStorage;

        // Setup temporary directory for test database
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test_scenario.db");

        println!("🔍 Starting register-login-logout-new-account scenario test");

        // Step 1: Register first user and login
        {
            println!("🔍 Step 1: Register and login first user");
            let auth_storage = AuthStorage::with_sqlite_persistence(db_path.clone(), "test_master_password")
                .await
                .expect("Failed to initialize auth storage");

            // Register first user
            let key_bundle1 = crate::commands::generate_key_bundle("password123".to_string()).await
                .expect("Failed to generate key bundle for user 1");

            let user1_result = auth_storage.register_user_with_keys(
                "alice".to_string(),
                "password123".to_string(),
                key_bundle1.private_keys
            ).await;
            assert!(user1_result.is_ok(), "Failed to register first user: {:?}", user1_result.err());

            // Login first user
            let login1_result = auth_storage.authenticate_user("alice".to_string(), "password123".to_string()).await;
            assert!(login1_result.is_ok(), "Failed to login first user: {:?}", login1_result.err());

            println!("✅ First user registered and logged in successfully");
        }

        // Step 2: Simulate logout by creating new auth storage instance
        {
            println!("🔍 Step 2: Simulate logout and create new account");
            let auth_storage = AuthStorage::with_sqlite_persistence(db_path.clone(), "test_master_password")
                .await
                .expect("Failed to initialize auth storage after logout");

            // Register second user (this should work without "Authentication tag verification failed")
            let key_bundle2 = crate::commands::generate_key_bundle("password456".to_string()).await
                .expect("Failed to generate key bundle for user 2");

            let user2_result = auth_storage.register_user_with_keys(
                "bob".to_string(),
                "password456".to_string(),
                key_bundle2.private_keys
            ).await;
            assert!(user2_result.is_ok(), "Failed to register second user: {:?}", user2_result.err());

            // Login second user
            let login2_result = auth_storage.authenticate_user("bob".to_string(), "password456".to_string()).await;
            assert!(login2_result.is_ok(), "Failed to login second user: {:?}", login2_result.err());

            // Also verify first user can still login
            let login1_again_result = auth_storage.authenticate_user("alice".to_string(), "password123".to_string()).await;
            assert!(login1_again_result.is_ok(), "Failed to login first user again: {:?}", login1_again_result.err());

            println!("✅ Second user registered and both users can login successfully");
        }

        println!("✅ Register-login-logout-new-account scenario test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_users_private_key_persistence_across_logout_login() -> Result<(), Box<dyn std::error::Error>> {
        use tempfile::TempDir;
        use crate::store::auth::AuthStorage;

        // Setup temporary directory for test database
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test_multi_user_persistence.db");

        println!("🔍 Starting multiple users private key persistence test");

        // User credentials
        let user1_username = "alice_persistence";
        let user1_password = "alice_password_123";
        let user2_username = "bob_persistence";
        let user2_password = "bob_password_456";

        // Step 1: Register both users and capture their initial private keys
        let (user1_initial_keys, user2_initial_keys) = {
            println!("🔍 Step 1: Register both users");
            let auth_storage = AuthStorage::with_sqlite_persistence(db_path.clone(), "test_master_password")
                .await
                .expect("Failed to initialize auth storage");

            // Register user 1
            let user1_key_bundle = crate::commands::generate_key_bundle(user1_password.to_string()).await
                .expect("Failed to generate key bundle for user 1");

            let user1_result = auth_storage.register_user_with_keys(
                user1_username.to_string(),
                user1_password.to_string(),
                user1_key_bundle.private_keys.clone()
            ).await;
            assert!(user1_result.is_ok(), "Failed to register user 1: {:?}", user1_result.err());

            // Register user 2
            let user2_key_bundle = crate::commands::generate_key_bundle(user2_password.to_string()).await
                .expect("Failed to generate key bundle for user 2");

            let user2_result = auth_storage.register_user_with_keys(
                user2_username.to_string(),
                user2_password.to_string(),
                user2_key_bundle.private_keys.clone()
            ).await;
            assert!(user2_result.is_ok(), "Failed to register user 2: {:?}", user2_result.err());

            println!("✅ Both users registered successfully");
            (user1_key_bundle.private_keys, user2_key_bundle.private_keys)
        };

        // Step 2: Login user 1, get keys, logout
        let user1_after_first_login_keys = {
            println!("🔍 Step 2: User 1 - First login");
            let auth_storage = AuthStorage::with_sqlite_persistence(db_path.clone(), "test_master_password")
                .await
                .expect("Failed to initialize auth storage for user 1 first login");

            // Login user 1
            let login_result = auth_storage.authenticate_user(user1_username.to_string(), user1_password.to_string()).await;
            assert!(login_result.is_ok(), "Failed to login user 1: {:?}", login_result.err());
            let user1 = login_result.unwrap();

            // Get private keys
            let keys_result = auth_storage.get_user_private_keys(&user1.id, user1_password).await;
            assert!(keys_result.is_ok(), "Failed to get user 1 private keys: {:?}", keys_result.err());

            let keys = keys_result.unwrap();
            println!("✅ User 1 first login successful, keys retrieved");
            keys
        };

        // Step 3: Login user 2, get keys, logout
        let user2_after_first_login_keys = {
            println!("🔍 Step 3: User 2 - First login");
            let auth_storage = AuthStorage::with_sqlite_persistence(db_path.clone(), "test_master_password")
                .await
                .expect("Failed to initialize auth storage for user 2 first login");

            // Login user 2
            let login_result = auth_storage.authenticate_user(user2_username.to_string(), user2_password.to_string()).await;
            assert!(login_result.is_ok(), "Failed to login user 2: {:?}", login_result.err());
            let user2 = login_result.unwrap();

            // Get private keys
            let keys_result = auth_storage.get_user_private_keys(&user2.id, user2_password).await;
            assert!(keys_result.is_ok(), "Failed to get user 2 private keys: {:?}", keys_result.err());

            let keys = keys_result.unwrap();
            println!("✅ User 2 first login successful, keys retrieved");
            keys
        };

        // Step 4: Login user 1 again after logout, verify keys are identical
        let user1_after_second_login_keys = {
            println!("🔍 Step 4: User 1 - Second login after logout");
            let auth_storage = AuthStorage::with_sqlite_persistence(db_path.clone(), "test_master_password")
                .await
                .expect("Failed to initialize auth storage for user 1 second login");

            // Login user 1 again
            let login_result = auth_storage.authenticate_user(user1_username.to_string(), user1_password.to_string()).await;
            assert!(login_result.is_ok(), "Failed to login user 1 second time: {:?}", login_result.err());
            let user1 = login_result.unwrap();

            // Get private keys again
            let keys_result = auth_storage.get_user_private_keys(&user1.id, user1_password).await;
            assert!(keys_result.is_ok(), "Failed to get user 1 private keys second time: {:?}", keys_result.err());

            let keys = keys_result.unwrap();
            println!("✅ User 1 second login successful, keys retrieved");
            keys
        };

        // Step 5: Login user 2 again after logout, verify keys are identical
        let user2_after_second_login_keys = {
            println!("🔍 Step 5: User 2 - Second login after logout");
            let auth_storage = AuthStorage::with_sqlite_persistence(db_path.clone(), "test_master_password")
                .await
                .expect("Failed to initialize auth storage for user 2 second login");

            // Login user 2 again
            let login_result = auth_storage.authenticate_user(user2_username.to_string(), user2_password.to_string()).await;
            assert!(login_result.is_ok(), "Failed to login user 2 second time: {:?}", login_result.err());
            let user2 = login_result.unwrap();

            // Get private keys again
            let keys_result = auth_storage.get_user_private_keys(&user2.id, user2_password).await;
            assert!(keys_result.is_ok(), "Failed to get user 2 private keys second time: {:?}", keys_result.err());

            let keys = keys_result.unwrap();
            println!("✅ User 2 second login successful, keys retrieved");
            keys
        };

        // Step 6: Verify all keys are consistent for each user
        println!("🔍 Step 6: Verifying private key persistence");

        // User 1 key consistency checks
        assert_eq!(
            user1_initial_keys.signed_pre_key,
            user1_after_first_login_keys.signed_pre_key,
            "User 1: Initial signed pre-key should match first login"
        );
        assert_eq!(
            user1_initial_keys.signed_pre_key,
            user1_after_second_login_keys.signed_pre_key,
            "User 1: Initial signed pre-key should match second login"
        );
        assert_eq!(
            user1_after_first_login_keys.signed_pre_key,
            user1_after_second_login_keys.signed_pre_key,
            "User 1: First login signed pre-key should match second login"
        );

        assert_eq!(
            user1_initial_keys.kyber_pre_key,
            user1_after_first_login_keys.kyber_pre_key,
            "User 1: Initial kyber pre-key should match first login"
        );
        assert_eq!(
            user1_initial_keys.kyber_pre_key,
            user1_after_second_login_keys.kyber_pre_key,
            "User 1: Initial kyber pre-key should match second login"
        );
        assert_eq!(
            user1_after_first_login_keys.kyber_pre_key,
            user1_after_second_login_keys.kyber_pre_key,
            "User 1: First login kyber pre-key should match second login"
        );

        assert_eq!(
            user1_initial_keys.identity_key,
            user1_after_first_login_keys.identity_key,
            "User 1: Initial identity key should match first login"
        );
        assert_eq!(
            user1_initial_keys.identity_key,
            user1_after_second_login_keys.identity_key,
            "User 1: Initial identity key should match second login"
        );
        assert_eq!(
            user1_after_first_login_keys.identity_key,
            user1_after_second_login_keys.identity_key,
            "User 1: First login identity key should match second login"
        );

        // User 2 key consistency checks
        assert_eq!(
            user2_initial_keys.signed_pre_key,
            user2_after_first_login_keys.signed_pre_key,
            "User 2: Initial signed pre-key should match first login"
        );
        assert_eq!(
            user2_initial_keys.signed_pre_key,
            user2_after_second_login_keys.signed_pre_key,
            "User 2: Initial signed pre-key should match second login"
        );
        assert_eq!(
            user2_after_first_login_keys.signed_pre_key,
            user2_after_second_login_keys.signed_pre_key,
            "User 2: First login signed pre-key should match second login"
        );

        assert_eq!(
            user2_initial_keys.kyber_pre_key,
            user2_after_first_login_keys.kyber_pre_key,
            "User 2: Initial kyber pre-key should match first login"
        );
        assert_eq!(
            user2_initial_keys.kyber_pre_key,
            user2_after_second_login_keys.kyber_pre_key,
            "User 2: Initial kyber pre-key should match second login"
        );
        assert_eq!(
            user2_after_first_login_keys.kyber_pre_key,
            user2_after_second_login_keys.kyber_pre_key,
            "User 2: First login kyber pre-key should match second login"
        );

        assert_eq!(
            user2_initial_keys.identity_key,
            user2_after_first_login_keys.identity_key,
            "User 2: Initial identity key should match first login"
        );
        assert_eq!(
            user2_initial_keys.identity_key,
            user2_after_second_login_keys.identity_key,
            "User 2: Initial identity key should match second login"
        );
        assert_eq!(
            user2_after_first_login_keys.identity_key,
            user2_after_second_login_keys.identity_key,
            "User 2: First login identity key should match second login"
        );

        // Verify users have different keys from each other
        assert_ne!(
            user1_after_second_login_keys.signed_pre_key,
            user2_after_second_login_keys.signed_pre_key,
            "User 1 and User 2 should have different signed pre-keys"
        );
        assert_ne!(
            user1_after_second_login_keys.kyber_pre_key,
            user2_after_second_login_keys.kyber_pre_key,
            "User 1 and User 2 should have different kyber pre-keys"
        );
        assert_ne!(
            user1_after_second_login_keys.identity_key,
            user2_after_second_login_keys.identity_key,
            "User 1 and User 2 should have different identity keys"
        );

        println!("✅ All private key persistence checks passed!");
        println!("✅ User 1 keys are consistent across logout/login cycles");
        println!("✅ User 2 keys are consistent across logout/login cycles");
        println!("✅ Users have different keys from each other");
        println!("✅ Multiple users private key persistence test passed");

        Ok(())
    }
}
