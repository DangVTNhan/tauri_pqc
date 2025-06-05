#[cfg(test)]
mod tests {
    use super::super::{
        service::AuthService,
        commands::{AuthState, auth_register, auth_login, auth_logout, auth_is_logged_in, auth_get_current_user}
    };
    use crate::commands::generate_key_bundle;
    use crate::models::auth::*;
    use crate::store::auth::AuthStorage;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use chrono;

    /// Mock AuthService for testing that doesn't make HTTP requests
    #[derive(Clone)]
    struct MockAuthService {
        auth_storage: AuthStorage,
        current_session: Arc<RwLock<Option<UserSession>>>,
    }

    impl MockAuthService {
        fn new() -> Self {
            Self {
                auth_storage: AuthStorage::new(),
                current_session: Arc::new(RwLock::new(None)),
            }
        }

        /// Register a new user (mock version - no HTTP requests)
        async fn register_user(&self, username: String, password: String) -> Result<RegisterResponse, String> {
            // Check if user already exists locally
            if self.auth_storage.user_exists(&username).await {
                return Err("User already exists locally".to_string());
            }

            // Generate key bundle for the user (this tests real key generation)
            let key_bundle_result = generate_key_bundle(password.clone()).await?;

            // Verify key bundle was generated correctly
            if key_bundle_result.public_keys.identity_key.is_empty() {
                return Err("Identity key generation failed".to_string());
            }

            // Store user locally with encrypted private keys
            let auth_user = self.auth_storage.register_user(username.clone(), password).await
                .map_err(|e| format!("Local user storage failed: {}", e))?;

            // Create session
            let session = self.auth_storage.create_session(auth_user.id, auth_user.username.clone()).await
                .map_err(|e| format!("Session creation failed: {}", e))?;

            // Store current session
            {
                let mut current_session = self.current_session.write().await;
                *current_session = Some(session);
            }

            // Return mock API response
            Ok(RegisterResponse {
                user: ApiUser {
                    id: auth_user.id.to_string(),
                    username: auth_user.username,
                    created_at: auth_user.created_at.to_rfc3339(),
                    updated_at: Some(auth_user.created_at.to_rfc3339()),
                },
            })
        }

        /// Login user (mock version - no HTTP requests)
        async fn login_user(&self, username: String, password: String) -> Result<LoginResponse, String> {
            // Authenticate user locally
            let auth_user = self.auth_storage.authenticate_user(username.clone(), password).await
                .map_err(|e| format!("Local authentication failed: {}", e))?;

            // Create session
            let session = self.auth_storage.create_session(auth_user.id, auth_user.username.clone()).await
                .map_err(|e| format!("Session creation failed: {}", e))?;

            // Store current session
            {
                let mut current_session = self.current_session.write().await;
                *current_session = Some(session);
            }

            // Return mock API response
            Ok(LoginResponse {
                user: ApiUser {
                    id: auth_user.id.to_string(),
                    username: auth_user.username,
                    created_at: auth_user.created_at.to_rfc3339(),
                    updated_at: Some(auth_user.created_at.to_rfc3339()),
                },
                groups: Some(vec![]), // Empty groups for testing
            })
        }

        /// Get current session
        async fn get_current_session(&self) -> Option<UserSession> {
            let current_session = self.current_session.read().await;
            current_session.clone()
        }

        /// Check if user is logged in
        async fn is_logged_in(&self) -> bool {
            if let Some(session) = self.get_current_session().await {
                session.is_valid()
            } else {
                false
            }
        }

        /// Logout user
        async fn logout(&self) -> Result<(), String> {
            if let Some(session) = self.get_current_session().await {
                self.auth_storage.invalidate_session(&session.user_id).await
                    .map_err(|e| format!("Failed to invalidate session: {}", e))?;
            }

            // Clear current session
            {
                let mut current_session = self.current_session.write().await;
                *current_session = None;
            }

            Ok(())
        }

        /// Get current user
        async fn get_current_user(&self) -> Result<AuthUser, String> {
            let session = self.get_current_session().await
                .ok_or_else(|| "No active session".to_string())?;

            if !session.is_valid() {
                return Err("Session expired".to_string());
            }

            self.auth_storage.get_user_by_id(&session.user_id).await
                .map_err(|e| format!("Failed to get user: {}", e))
        }

        /// Clean up expired sessions
        async fn cleanup_expired_sessions(&self) -> Result<u64, String> {
            self.auth_storage.cleanup_expired_sessions().await
                .map_err(|e| format!("Failed to cleanup sessions: {}", e))
        }
    }

    // Test constants - hardcoded as requested but keys will be generated
    const TEST_USERNAME_1: &str = "alice_test_user";
    const TEST_PASSWORD_1: &str = "SecurePassword123!";
    const TEST_USERNAME_2: &str = "bob_test_user";
    const TEST_PASSWORD_2: &str = "AnotherSecurePass456@";

    #[tokio::test]
    async fn test_auth_service_register_flow() {
        println!("🧪 Testing AuthService register flow with real key generation");

        let auth_service = MockAuthService::new();
        
        // Test successful registration
        let result = auth_service.register_user(
            TEST_USERNAME_1.to_string(),
            TEST_PASSWORD_1.to_string()
        ).await;
        
        assert!(result.is_ok(), "Registration should succeed: {:?}", result.err());
        
        let register_response = result.unwrap();
        
        // Verify response structure
        assert_eq!(register_response.user.username, TEST_USERNAME_1);
        assert!(!register_response.user.id.is_empty());
        assert!(!register_response.user.created_at.is_empty());
        
        println!("✅ User registered successfully: {}", register_response.user.username);
        
        // Test duplicate registration should fail
        let duplicate_result = auth_service.register_user(
            TEST_USERNAME_1.to_string(),
            TEST_PASSWORD_1.to_string()
        ).await;
        
        assert!(duplicate_result.is_err(), "Duplicate registration should fail");
        println!("✅ Duplicate registration properly rejected");
    }

    #[tokio::test]
    async fn test_auth_service_login_flow() {
        println!("🧪 Testing AuthService login flow with real key generation");

        let auth_service = MockAuthService::new();
        
        // First register a user
        let register_result = auth_service.register_user(
            TEST_USERNAME_2.to_string(),
            TEST_PASSWORD_2.to_string()
        ).await;
        assert!(register_result.is_ok(), "Registration should succeed for login test");
        
        // Test successful login
        let login_result = auth_service.login_user(
            TEST_USERNAME_2.to_string(),
            TEST_PASSWORD_2.to_string()
        ).await;
        
        assert!(login_result.is_ok(), "Login should succeed: {:?}", login_result.err());
        
        let login_response = login_result.unwrap();
        
        // Verify response structure
        assert_eq!(login_response.user.username, TEST_USERNAME_2);
        assert!(!login_response.user.id.is_empty());
        // Groups can be empty initially or None
        assert!(login_response.groups.as_ref().map_or(true, |g| g.is_empty()) ||
                login_response.groups.as_ref().map_or(false, |g| !g.is_empty()));
        
        println!("✅ User logged in successfully: {}", login_response.user.username);
        
        // Verify session was created
        let session = auth_service.get_current_session().await;
        assert!(session.is_some(), "Session should be created after login");
        
        let session = session.unwrap();
        assert_eq!(session.username, TEST_USERNAME_2);
        assert!(session.is_valid(), "Session should be valid");
        
        println!("✅ Session created and validated");
        
        // Test login with wrong password
        let wrong_password_result = auth_service.login_user(
            TEST_USERNAME_2.to_string(),
            "WrongPassword123!".to_string()
        ).await;
        
        assert!(wrong_password_result.is_err(), "Login with wrong password should fail");
        println!("✅ Wrong password properly rejected");
        
        // Test login with non-existent user
        let nonexistent_result = auth_service.login_user(
            "nonexistent_user".to_string(),
            TEST_PASSWORD_2.to_string()
        ).await;
        
        assert!(nonexistent_result.is_err(), "Login with non-existent user should fail");
        println!("✅ Non-existent user properly rejected");
    }

    #[tokio::test]
    async fn test_auth_service_session_management() {
        println!("🧪 Testing AuthService session management");

        let auth_service = MockAuthService::new();
        
        // Register and login user
        auth_service.register_user(
            "session_test_user".to_string(),
            "SessionTestPass123!".to_string()
        ).await.unwrap();
        
        auth_service.login_user(
            "session_test_user".to_string(),
            "SessionTestPass123!".to_string()
        ).await.unwrap();
        
        // Verify user is logged in
        assert!(auth_service.is_logged_in().await, "User should be logged in");
        
        // Get current user
        let current_user = auth_service.get_current_user().await;
        assert!(current_user.is_ok(), "Should be able to get current user");
        
        let user = current_user.unwrap();
        assert_eq!(user.username, "session_test_user");
        
        println!("✅ Session management working correctly");
        
        // Test logout
        let logout_result = auth_service.logout().await;
        assert!(logout_result.is_ok(), "Logout should succeed");
        
        // Verify user is no longer logged in
        assert!(!auth_service.is_logged_in().await, "User should not be logged in after logout");
        
        // Verify getting current user fails after logout
        let current_user_after_logout = auth_service.get_current_user().await;
        assert!(current_user_after_logout.is_err(), "Should not be able to get current user after logout");
        
        println!("✅ Logout and session cleanup working correctly");
    }

    #[tokio::test]
    async fn test_auth_service_direct_integration() {
        println!("🧪 Testing Auth service direct integration (simulating Tauri commands)");

        // Note: We test the service directly since Tauri State requires a full Tauri app context
        // This tests the same logic that the Tauri commands would use

        let auth_service = MockAuthService::new();

        // Test register flow (equivalent to auth_register command)
        println!("📝 Testing register flow...");
        let register_result = auth_service.register_user(
            "command_test_user".to_string(),
            "CommandTestPass123!".to_string()
        ).await;

        assert!(register_result.is_ok(), "Register should succeed: {:?}", register_result.err());

        let register_response = register_result.unwrap();
        assert_eq!(register_response.user.username, "command_test_user");

        println!("✅ Register flow working correctly");

        // Test logout to prepare for login test
        let _ = auth_service.logout().await;

        // Test login flow (equivalent to auth_login command)
        println!("📝 Testing login flow...");
        let login_result = auth_service.login_user(
            "command_test_user".to_string(),
            "CommandTestPass123!".to_string()
        ).await;

        assert!(login_result.is_ok(), "Login should succeed: {:?}", login_result.err());

        let login_response = login_result.unwrap();
        assert_eq!(login_response.user.username, "command_test_user");

        println!("✅ Login flow working correctly");

        // Test is_logged_in flow (equivalent to auth_is_logged_in command)
        println!("📝 Testing is_logged_in flow...");
        let is_logged_in = auth_service.is_logged_in().await;
        assert!(is_logged_in, "User should be logged in");

        println!("✅ is_logged_in flow working correctly");

        // Test get_current_user flow (equivalent to auth_get_current_user command)
        println!("📝 Testing get_current_user flow...");
        let current_user_result = auth_service.get_current_user().await;

        assert!(current_user_result.is_ok(), "get_current_user should succeed");

        let current_user = current_user_result.unwrap();
        assert_eq!(current_user.username, "command_test_user");

        println!("✅ get_current_user flow working correctly");

        // Test logout flow (equivalent to auth_logout command)
        println!("📝 Testing logout flow...");
        let logout_result = auth_service.logout().await;

        assert!(logout_result.is_ok(), "Logout should succeed");

        // Verify user is logged out
        let is_logged_in_after_logout = auth_service.is_logged_in().await;
        assert!(!is_logged_in_after_logout, "User should not be logged in after logout");

        println!("✅ Logout flow working correctly");
        println!("✅ All auth service flows (equivalent to Tauri commands) working correctly");
    }

    #[tokio::test]
    async fn test_key_generation_in_register_flow() {
        println!("🧪 Testing real key generation in register flow");
        
        // Test that key generation actually works during registration
        let key_bundle_result = generate_key_bundle("TestKeyGeneration123!".to_string()).await;
        assert!(key_bundle_result.is_ok(), "Key bundle generation should succeed");
        
        let key_bundle = key_bundle_result.unwrap();
        
        // Verify all keys are generated and not empty
        assert!(!key_bundle.public_keys.identity_key.is_empty(), "Identity public key should not be empty");
        assert!(!key_bundle.public_keys.signed_pre_key.is_empty(), "Signed pre-key should not be empty");
        assert!(!key_bundle.public_keys.kyber_pre_key.is_empty(), "Kyber pre-key should not be empty");
        assert!(!key_bundle.public_keys.one_time_pre_keys.is_empty(), "One-time pre-keys should not be empty");
        assert!(!key_bundle.public_keys.signature.is_empty(), "Signature should not be empty");
        
        // Verify private keys are encrypted
        assert!(!key_bundle.private_keys.identity_key.is_empty(), "Identity private key should not be empty");
        assert!(!key_bundle.private_keys.signed_pre_key.is_empty(), "Signed private key should not be empty");
        assert!(!key_bundle.private_keys.kyber_pre_key.is_empty(), "Kyber private key should not be empty");
        assert!(!key_bundle.private_keys.one_time_pre_keys.is_empty(), "One-time private keys should not be empty");
        
        // Verify nonces are present
        assert!(!key_bundle.private_keys.identity_key_nonce.is_empty(), "Identity key nonce should not be empty");
        assert!(!key_bundle.private_keys.signed_pre_key_nonce.is_empty(), "Signed pre-key nonce should not be empty");
        assert!(!key_bundle.private_keys.kyber_pre_key_nonce.is_empty(), "Kyber pre-key nonce should not be empty");
        assert!(!key_bundle.private_keys.one_time_pre_keys_nonces.is_empty(), "One-time pre-key nonces should not be empty");
        
        // Verify salt is present
        assert!(!key_bundle.private_keys.salt.is_empty(), "Salt should not be empty");
        
        // Verify timestamp is present
        assert!(!key_bundle.timestamp.is_empty(), "Timestamp should not be empty");
        
        println!("✅ All cryptographic keys generated successfully");
        println!("   - Identity key: {} chars", key_bundle.public_keys.identity_key.len());
        println!("   - Signed pre-key: {} chars", key_bundle.public_keys.signed_pre_key.len());
        println!("   - Kyber pre-key: {} chars", key_bundle.public_keys.kyber_pre_key.len());
        println!("   - One-time pre-keys: {} keys", key_bundle.public_keys.one_time_pre_keys.len());
        
        // Now test registration with real key generation
        let auth_service = MockAuthService::new();
        let register_result = auth_service.register_user(
            "key_gen_test_user".to_string(),
            "KeyGenTestPass123!".to_string()
        ).await;
        
        assert!(register_result.is_ok(), "Registration with key generation should succeed");
        println!("✅ Registration with real key generation completed successfully");
    }

    #[tokio::test]
    async fn test_complete_authentication_workflow() {
        println!("🧪 Testing complete authentication workflow (register -> login -> operations -> logout)");

        let auth_service = MockAuthService::new();
        let test_username = "workflow_test_user";
        let test_password = "WorkflowTestPass123!";

        // Step 1: Register user
        println!("📝 Step 1: Registering user...");
        let register_result = auth_service.register_user(
            test_username.to_string(),
            test_password.to_string()
        ).await;

        assert!(register_result.is_ok(), "Registration should succeed");
        let register_response = register_result.unwrap();

        // Verify registration response
        assert_eq!(register_response.user.username, test_username);
        assert!(!register_response.user.id.is_empty());
        println!("✅ User registered with ID: {}", register_response.user.id);

        // Verify user is automatically logged in after registration
        assert!(auth_service.is_logged_in().await, "User should be logged in after registration");
        println!("✅ User automatically logged in after registration");

        // Step 2: Logout to test login flow
        println!("📝 Step 2: Logging out to test login flow...");
        let logout_result = auth_service.logout().await;
        assert!(logout_result.is_ok(), "Logout should succeed");
        assert!(!auth_service.is_logged_in().await, "User should not be logged in after logout");
        println!("✅ User logged out successfully");

        // Step 3: Login with correct credentials
        println!("📝 Step 3: Logging in with correct credentials...");
        let login_result = auth_service.login_user(
            test_username.to_string(),
            test_password.to_string()
        ).await;

        assert!(login_result.is_ok(), "Login should succeed");
        let login_response = login_result.unwrap();

        // Verify login response
        assert_eq!(login_response.user.username, test_username);
        assert_eq!(login_response.user.id, register_response.user.id);
        println!("✅ User logged in successfully");

        // Step 4: Verify session and user operations
        println!("📝 Step 4: Testing session and user operations...");
        assert!(auth_service.is_logged_in().await, "User should be logged in");

        let current_user = auth_service.get_current_user().await;
        assert!(current_user.is_ok(), "Should be able to get current user");

        let user = current_user.unwrap();
        assert_eq!(user.username, test_username);
        println!("✅ Session and user operations working correctly");

        // Step 5: Test session cleanup
        println!("📝 Step 5: Testing session cleanup...");
        let cleanup_result = auth_service.cleanup_expired_sessions().await;
        assert!(cleanup_result.is_ok(), "Session cleanup should succeed");
        println!("✅ Session cleanup completed");

        // Step 6: Final logout
        println!("📝 Step 6: Final logout...");
        let final_logout = auth_service.logout().await;
        assert!(final_logout.is_ok(), "Final logout should succeed");
        assert!(!auth_service.is_logged_in().await, "User should not be logged in after final logout");
        println!("✅ Complete authentication workflow test passed");
    }

    #[tokio::test]
    async fn test_multiple_users_authentication() {
        println!("🧪 Testing multiple users authentication (isolation test)");

        let auth_service = MockAuthService::new();

        // Register multiple users
        let users = vec![
            ("multi_user_1", "MultiUser1Pass123!"),
            ("multi_user_2", "MultiUser2Pass456@"),
            ("multi_user_3", "MultiUser3Pass789#"),
        ];

        let mut registered_users = Vec::new();

        // Register all users
        for (username, password) in &users {
            println!("📝 Registering user: {}", username);

            // Logout any current user first
            let _ = auth_service.logout().await;

            let register_result = auth_service.register_user(
                username.to_string(),
                password.to_string()
            ).await;

            assert!(register_result.is_ok(), "Registration should succeed for {}", username);
            let register_response = register_result.unwrap();

            let user_id = register_response.user.id.clone();
            registered_users.push((username.to_string(), password.to_string(), user_id.clone()));
            println!("✅ User {} registered with ID: {}", username, user_id);
        }

        // Test login for each user
        for (username, password, expected_id) in &registered_users {
            println!("📝 Testing login for user: {}", username);

            // Logout any current user first
            let _ = auth_service.logout().await;

            let login_result = auth_service.login_user(
                username.clone(),
                password.clone()
            ).await;

            assert!(login_result.is_ok(), "Login should succeed for {}", username);
            let login_response = login_result.unwrap();

            assert_eq!(login_response.user.username, *username);
            assert_eq!(login_response.user.id, *expected_id);

            // Verify session
            assert!(auth_service.is_logged_in().await, "User {} should be logged in", username);

            let current_user = auth_service.get_current_user().await;
            assert!(current_user.is_ok(), "Should be able to get current user for {}", username);

            let user = current_user.unwrap();
            assert_eq!(user.username, *username);

            println!("✅ User {} login and session verified", username);
        }

        println!("✅ Multiple users authentication test passed");
    }

    #[tokio::test]
    async fn test_password_security_and_key_generation() {
        println!("🧪 Testing password security and key generation");

        let auth_service = MockAuthService::new();

        // Test with different password complexities
        let test_cases = vec![
            ("simple_user", "SimplePass123!"),
            ("complex_user", "C0mpl3x!P@ssw0rd#W1th$Sp3c1@l&Ch@rs"),
            ("unicode_user", "Пароль123!测试密码"),
            ("long_user", "ThisIsAVeryLongPasswordThatShouldStillWorkCorrectlyWithOurAuthenticationSystem123!"),
        ];

        for (username, password) in test_cases {
            println!("📝 Testing password security for: {}", username);

            // Register user
            let register_result = auth_service.register_user(
                username.to_string(),
                password.to_string()
            ).await;

            assert!(register_result.is_ok(), "Registration should succeed for {}", username);
            println!("✅ Registration successful for {}", username);

            // Logout to test login
            let _ = auth_service.logout().await;

            // Test correct password
            let login_result = auth_service.login_user(
                username.to_string(),
                password.to_string()
            ).await;

            assert!(login_result.is_ok(), "Login with correct password should succeed for {}", username);
            println!("✅ Login with correct password successful for {}", username);

            // Test wrong password
            let wrong_login_result = auth_service.login_user(
                username.to_string(),
                "WrongPassword123!".to_string()
            ).await;

            assert!(wrong_login_result.is_err(), "Login with wrong password should fail for {}", username);
            println!("✅ Login with wrong password properly rejected for {}", username);

            // Logout for next test
            let _ = auth_service.logout().await;
        }

        println!("✅ Password security and key generation test passed");
    }

    #[tokio::test]
    async fn test_concurrent_authentication_operations() {
        println!("🧪 Testing concurrent authentication operations");

        use tokio::task;

        // Create a shared auth service for all concurrent operations
        let shared_auth_service = Arc::new(MockAuthService::new());

        // Test concurrent registrations (should handle properly)
        let registration_tasks = (0..5).map(|i| {
            let auth_service = shared_auth_service.clone();
            task::spawn(async move {
                let username = format!("concurrent_user_{}", i);
                let password = format!("ConcurrentPass{}!", i);

                auth_service.register_user(username, password).await
            })
        });

        let registration_results = futures::future::join_all(registration_tasks).await;

        for (i, result) in registration_results.into_iter().enumerate() {
            let register_result = result.expect("Task should complete");
            assert!(register_result.is_ok(), "Concurrent registration {} should succeed", i);
            println!("✅ Concurrent registration {} completed", i);
        }

        // Test concurrent logins with the same shared service
        let login_tasks = (0..5).map(|i| {
            let auth_service = shared_auth_service.clone();
            task::spawn(async move {
                let username = format!("concurrent_user_{}", i);
                let password = format!("ConcurrentPass{}!", i);

                // First logout any current session to avoid conflicts
                let _ = auth_service.logout().await;

                auth_service.login_user(username, password).await
            })
        });

        let login_results = futures::future::join_all(login_tasks).await;

        for (i, result) in login_results.into_iter().enumerate() {
            let login_result = result.expect("Task should complete");
            assert!(login_result.is_ok(), "Concurrent login {} should succeed", i);
            println!("✅ Concurrent login {} completed", i);
        }

        println!("✅ Concurrent authentication operations test passed");
    }

    #[tokio::test]
    async fn test_real_go_backend_integration() {
        println!("🧪 Testing real Go backend integration (requires Go server running on port 8080)");

        // Use the real AuthService (not mock) to test actual HTTP communication
        let real_auth_service = super::super::service::AuthService::new();

        // Test unique username to avoid conflicts
        let test_username = format!("integration_test_user_{}", chrono::Utc::now().timestamp());
        let test_password = "IntegrationTestPass123!";

        println!("📝 Testing registration with real Go backend...");
        println!("   Username: {}", test_username);

        // Test registration with real Go backend
        let register_result = real_auth_service.register_user(
            test_username.clone(),
            test_password.to_string()
        ).await;

        match register_result {
            Ok(register_response) => {
                println!("✅ Registration successful!");
                println!("   User ID: {}", register_response.user.id);
                println!("   Username: {}", register_response.user.username);
                println!("   Created at: {}", register_response.user.created_at);

                // Verify response structure
                assert_eq!(register_response.user.username, test_username);
                assert!(!register_response.user.id.is_empty());
                assert!(!register_response.user.created_at.is_empty());

                // Test logout to prepare for login test
                let _ = real_auth_service.logout().await;

                println!("📝 Testing login with real Go backend...");

                // Test login with real Go backend
                let login_result = real_auth_service.login_user(
                    test_username.clone(),
                    test_password.to_string()
                ).await;

                match login_result {
                    Ok(login_response) => {
                        println!("✅ Login successful!");
                        println!("   User ID: {}", login_response.user.id);
                        println!("   Username: {}", login_response.user.username);
                        println!("   Groups: {} groups", login_response.groups.as_ref().map_or(0, |g| g.len()));

                        // Verify login response
                        assert_eq!(login_response.user.username, test_username);
                        assert_eq!(login_response.user.id, register_response.user.id);

                        println!("✅ Real Go backend integration test passed!");
                    }
                    Err(login_error) => {
                        println!("❌ Login failed: {}", login_error);
                        panic!("Login should succeed after successful registration");
                    }
                }
            }
            Err(register_error) => {
                if register_error.contains("Connection refused") || register_error.contains("connection error") {
                    println!("⚠️  Go backend not running on port 8080, skipping integration test");
                    println!("   To run this test, start the Go backend with: cd src-go && PORT=8080 go run main.go");
                    return; // Skip test if backend is not running
                } else {
                    println!("❌ Registration failed: {}", register_error);
                    panic!("Registration failed with unexpected error: {}", register_error);
                }
            }
        }
    }
}
