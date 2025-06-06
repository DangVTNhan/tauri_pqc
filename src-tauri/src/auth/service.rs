use crate::http::ApiClient;
use crate::models::auth::*;
use crate::store::auth::AuthStorage;
use crate::commands::generate_key_bundle;
use base64::Engine;
use std::sync::Arc;
use std::path::PathBuf;
use tokio::sync::RwLock;

/// Authentication service that manages user registration, login, and session management
#[derive(Clone)]
pub struct AuthService {
    auth_storage: AuthStorage,
    api_client: ApiClient,
    current_session: Arc<RwLock<Option<UserSession>>>,
}

impl AuthService {
    /// Create a new authentication service with in-memory storage
    pub fn new() -> Self {
        Self {
            auth_storage: AuthStorage::new(),
            api_client: ApiClient::default(),
            current_session: Arc::new(RwLock::new(None)),
        }
    }

    /// Create a new authentication service with encrypted SQLite persistence
    pub async fn with_sqlite_persistence(db_path: PathBuf, master_password: &str) -> Result<Self, String> {
        let auth_storage = AuthStorage::with_sqlite_persistence(db_path, master_password).await
            .map_err(|e| format!("Failed to initialize SQLite auth storage: {}", e))?;

        Ok(Self {
            auth_storage,
            api_client: ApiClient::default(),
            current_session: Arc::new(RwLock::new(None)),
        })
    }

    /// Register a new user
    pub async fn register_user(&self, username: String, password: String) -> Result<RegisterResponse, String> {
        // Check if user already exists locally
        if self.auth_storage.user_exists(&username).await {
            return Err("User already exists locally".to_string());
        }

        // Generate key bundle for the user
        let key_bundle_result = generate_key_bundle(password.clone()).await?;

        // Convert base64 strings to byte arrays for API communication
        let base64_engine = base64::engine::general_purpose::STANDARD;

        // Convert public keys from base64 strings to byte arrays
        let api_public_keys = ApiPublicKeyBundle {
            identity_key: base64_engine.decode(&key_bundle_result.public_keys.identity_key)
                .map_err(|e| format!("Failed to decode identity key: {}", e))?,
            signed_pre_key: base64_engine.decode(&key_bundle_result.public_keys.signed_pre_key)
                .map_err(|e| format!("Failed to decode signed pre-key: {}", e))?,
            kyber_pre_key: base64_engine.decode(&key_bundle_result.public_keys.kyber_pre_key)
                .map_err(|e| format!("Failed to decode kyber pre-key: {}", e))?,
            one_time_pre_keys: key_bundle_result.public_keys.one_time_pre_keys.iter()
                .map(|key| base64_engine.decode(key))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("Failed to decode one-time pre-keys: {}", e))?,
            signature: base64_engine.decode(&key_bundle_result.public_keys.signature)
                .map_err(|e| format!("Failed to decode signature: {}", e))?,
        };

        // SECURITY: Only send public keys to server - NEVER private keys or passwords
        let api_request = ApiRegisterRequest {
            username: username.clone(),
            public_key_bundle: api_public_keys,
        };

        // The Go backend returns a wrapped response structure, so we need to handle it properly
        let api_response = self.api_client.post::<serde_json::Value, _>("/register", &api_request).await
            .map_err(|e| format!("API registration failed: {}", e))?;

        if !api_response.success {
            return Err(api_response.error.unwrap_or_else(|| "Registration failed".to_string()));
        }

        let response_data = api_response.data
            .ok_or_else(|| "No data in registration response".to_string())?;

        // Parse the nested response structure
        let register_response: RegisterResponse = serde_json::from_value(response_data)
            .map_err(|e| format!("Failed to parse registration response: {}", e))?;

        // Store user locally with encrypted private keys and key bundle
        let auth_user = self.auth_storage.register_user_with_keys(username, password, key_bundle_result.private_keys.clone()).await
            .map_err(|e| format!("Local user storage failed: {}", e))?;

        // Create session
        let session = self.auth_storage.create_session(auth_user.id, auth_user.username.clone()).await
            .map_err(|e| format!("Session creation failed: {}", e))?;

        // Store current session
        {
            let mut current_session = self.current_session.write().await;
            *current_session = Some(session);
        }

        Ok(register_response)
    }

    /// Login user
    pub async fn login_user(&self, username: String, password: String) -> Result<LoginResponse, String> {
        // Authenticate user locally
        let auth_user = self.auth_storage.authenticate_user(username.clone(), password.clone()).await
            .map_err(|e| format!("Local authentication failed: {}", e))?;

        // Login with Go API server (SECURITY: No password sent)
        let api_request = ApiLoginRequest {
            username: username.clone(),
        };

        // The Go backend returns a wrapped response structure, so we need to handle it properly
        let api_response = self.api_client.post::<serde_json::Value, _>("/login", &api_request).await
            .map_err(|e| format!("API login failed: {}", e))?;

        if !api_response.success {
            return Err(api_response.error.unwrap_or_else(|| "Login failed".to_string()));
        }

        let response_data = api_response.data
            .ok_or_else(|| "No data in login response".to_string())?;

        // Parse the nested response structure
        let login_response: LoginResponse = serde_json::from_value(response_data)
            .map_err(|e| format!("Failed to parse login response: {}", e))?;

        // Fetch pending messages from server
        let messages_response = self.api_client.get::<UserMessagesResponse>(&format!("/users/{}/messages", auth_user.id)).await;
        
        if let Ok(messages_api_response) = messages_response {
            if messages_api_response.success {
                if let Some(messages_data) = messages_api_response.data {
                    println!("Fetched {} pending messages for user {}", messages_data.count, username);
                    // TODO: Store pending messages in local database
                    // This would include key exchange requests, group invitations, file sharing requests
                }
            }
        }

        // Create session
        let session = self.auth_storage.create_session(auth_user.id, auth_user.username.clone()).await
            .map_err(|e| format!("Session creation failed: {}", e))?;

        // Store current session
        {
            let mut current_session = self.current_session.write().await;
            *current_session = Some(session);
        }

        Ok(login_response)
    }

    /// Get current session
    pub async fn get_current_session(&self) -> Option<UserSession> {
        let current_session = self.current_session.read().await;
        current_session.clone()
    }

    /// Check if user is logged in
    pub async fn is_logged_in(&self) -> bool {
        if let Some(session) = self.get_current_session().await {
            session.is_valid()
        } else {
            false
        }
    }

    /// Logout user
    pub async fn logout(&self) -> Result<(), String> {
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
    pub async fn get_current_user(&self) -> Result<AuthUser, String> {
        let session = self.get_current_session().await
            .ok_or_else(|| "No active session".to_string())?;

        if !session.is_valid() {
            return Err("Session expired".to_string());
        }

        self.auth_storage.get_user_by_id(&session.user_id).await
            .map_err(|e| format!("Failed to get user: {}", e))
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<u64, String> {
        self.auth_storage.cleanup_expired_sessions().await
            .map_err(|e| format!("Failed to cleanup sessions: {}", e))
    }

    /// Get user's private keys by decrypting them with password
    pub async fn get_user_private_keys(&self, user_id: &uuid::Uuid, password: &str) -> Result<crate::commands::PrivateKeyBundleResult, String> {
        self.auth_storage.get_user_private_keys(user_id, password).await
            .map_err(|e| format!("Failed to get private keys: {}", e))
    }
}

impl Default for AuthService {
    fn default() -> Self {
        Self::new()
    }
}
