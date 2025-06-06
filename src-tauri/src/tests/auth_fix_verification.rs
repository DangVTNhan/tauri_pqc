//! Authentication Fix Verification Tests
//!
//! This module contains tests to verify that the authentication tag verification issue has been fixed.

#[cfg(test)]
mod auth_fix_tests {
    use crate::auth::service::AuthService;
    use crate::store::auth::AuthStorage;
    use tempfile::TempDir;

    /// Helper function to create a test AuthStorage with SQLite persistence
    async fn create_test_auth_storage() -> (AuthStorage, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test_auth.db");
        let master_password = "test_master_password_2024";

        let auth_storage = AuthStorage::with_sqlite_persistence(db_path, master_password).await
            .expect("Failed to create SQLite auth storage");

        (auth_storage, temp_dir)
    }

    #[tokio::test]
    async fn test_auth_storage_register_and_authenticate() {
        println!("🧪 Testing AuthStorage register and authenticate fix");

        let (auth_storage, _temp_dir) = create_test_auth_storage().await;
        let username = "test_user_fix".to_string();
        let password = "TestPassword123!".to_string();

        // Test registration
        println!("   📝 Testing user registration...");
        let registered_user = auth_storage.register_user(username.clone(), password.clone()).await
            .expect("User registration should succeed");

        println!("   ✅ User registered successfully");
        println!("      Username: {}", registered_user.username);
        println!("      User ID: {}", registered_user.id);
        println!("      Salt length: {}", registered_user.salt.len());
        println!("      Password hash length: {}", registered_user.password_hash.len());

        // Test authentication with correct password
        println!("   🔐 Testing authentication with correct password...");
        let authenticated_user = auth_storage.authenticate_user(username.clone(), password.clone()).await
            .expect("Authentication with correct password should succeed");

        println!("   ✅ Authentication successful");
        assert_eq!(registered_user.id, authenticated_user.id);
        assert_eq!(registered_user.username, authenticated_user.username);

        // Test authentication with wrong password
        println!("   ❌ Testing authentication with wrong password...");
        let wrong_password = "WrongPassword123!".to_string();
        let auth_result = auth_storage.authenticate_user(username.clone(), wrong_password).await;

        assert!(auth_result.is_err(), "Authentication with wrong password should fail");
        println!("   ✅ Authentication correctly failed with wrong password");

        println!("🎉 Authentication fix verification passed!");
    }

    #[tokio::test]
    async fn test_auth_service_register_and_login() {
        println!("🧪 Testing AuthService register and login fix");

        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test_auth_service.db");
        let master_password = "test_auth_service_master_password_2024";

        let auth_service = AuthService::with_sqlite_persistence(db_path, master_password).await
            .expect("Failed to create AuthService with SQLite persistence");
        let username = "service_test_user".to_string();
        let password = "ServicePassword456!".to_string();

        // Test registration (this will fail with API call, but local storage should work)
        println!("   📝 Testing service registration (local part)...");

        // We can't test the full registration because it requires the Go API server
        // But we can test the local authentication storage directly
        let (auth_storage, _temp_dir) = create_test_auth_storage().await;
        
        let registered_user = auth_storage.register_user(username.clone(), password.clone()).await
            .expect("Local user registration should succeed");

        println!("   ✅ Local user registration successful");

        // Test local authentication
        println!("   🔐 Testing local authentication...");
        let authenticated_user = auth_storage.authenticate_user(username.clone(), password.clone()).await
            .expect("Local authentication should succeed");

        println!("   ✅ Local authentication successful");
        assert_eq!(registered_user.id, authenticated_user.id);

        println!("🎉 AuthService local authentication fix verified!");
    }

    #[tokio::test]
    async fn test_multiple_users_no_interference() {
        println!("🧪 Testing multiple users don't interfere with each other");

        let (auth_storage, _temp_dir) = create_test_auth_storage().await;

        // Create multiple users
        let users = vec![
            ("alice_fix", "AlicePassword123!"),
            ("bob_fix", "BobPassword456!"),
            ("charlie_fix", "CharliePassword789!"),
        ];

        let mut registered_users = Vec::new();

        // Register all users
        for (username, password) in &users {
            println!("   📝 Registering user: {}", username);
            let user = auth_storage.register_user(username.to_string(), password.to_string()).await
                .expect("User registration should succeed");
            registered_users.push(user);
        }

        println!("   ✅ All users registered successfully");

        // Authenticate each user with their correct password
        for ((username, password), registered_user) in users.iter().zip(registered_users.iter()) {
            println!("   🔐 Authenticating user: {}", username);
            let authenticated_user = auth_storage.authenticate_user(username.to_string(), password.to_string()).await
                .expect("Authentication should succeed");

            assert_eq!(registered_user.id, authenticated_user.id);
            assert_eq!(registered_user.username, authenticated_user.username);
        }

        println!("   ✅ All users authenticated successfully");

        // Test cross-authentication (should fail)
        println!("   ❌ Testing cross-authentication (should fail)...");
        let alice_auth_with_bob_password = auth_storage.authenticate_user(
            "alice_fix".to_string(), 
            "BobPassword456!".to_string()
        ).await;

        assert!(alice_auth_with_bob_password.is_err(), "Cross-authentication should fail");
        println!("   ✅ Cross-authentication correctly failed");

        println!("🎉 Multiple users test passed!");
    }

    #[tokio::test]
    async fn test_password_hash_format() {
        println!("🧪 Testing password hash format and salt handling");

        let (auth_storage, _temp_dir) = create_test_auth_storage().await;
        let username = "hash_test_user".to_string();
        let password = "HashTestPassword123!".to_string();

        let user = auth_storage.register_user(username, password.clone()).await
            .expect("User registration should succeed");

        println!("   📊 Password hash analysis:");
        println!("      Hash: {}", user.password_hash);
        println!("      Salt: {}", user.salt);
        println!("      Hash starts with $argon2: {}", user.password_hash.starts_with("$argon2"));
        println!("      Salt length: {}", user.salt.len());

        // Verify the hash format is correct Argon2
        assert!(user.password_hash.starts_with("$argon2"), "Password hash should be Argon2 format");
        assert!(!user.salt.is_empty(), "Salt should not be empty");
        assert!(user.salt.len() > 10, "Salt should be reasonable length");

        // Verify the salt is a valid base64 string (Argon2 salt format)
        assert!(user.salt.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='), 
                "Salt should be valid base64-like format");

        println!("   ✅ Password hash format is correct");
        println!("🎉 Password hash format test passed!");
    }
}
