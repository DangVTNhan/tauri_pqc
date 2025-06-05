use crate::models::auth::{AuthUser, UserSession};
use crate::store::{StorageError, StorageResult};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use uuid::Uuid;
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;

/// Authentication storage service for managing user credentials and sessions
#[derive(Clone)]
pub struct AuthStorage {
    users: Arc<RwLock<HashMap<String, AuthUser>>>, // username -> user
    sessions: Arc<RwLock<HashMap<Uuid, UserSession>>>, // user_id -> session
    user_by_id: Arc<RwLock<HashMap<Uuid, String>>>, // user_id -> username
}

impl AuthStorage {
    /// Create a new authentication storage instance
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            user_by_id: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new user with password hashing
    pub async fn register_user(&self, username: String, password: String) -> StorageResult<AuthUser> {
        // Check if user already exists
        {
            let users = self.users.read().await;
            if users.contains_key(&username) {
                return Err(StorageError::configuration(format!("User {} already exists", username)));
            }
        }

        // Hash password with Argon2
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| StorageError::encryption(format!("Password hashing failed: {}", e)))?
            .to_string();

        // Create user
        let user = AuthUser::new(username.clone(), password_hash, salt.to_string().into_bytes());

        // Store user
        {
            let mut users = self.users.write().await;
            let mut user_by_id = self.user_by_id.write().await;
            
            users.insert(username.clone(), user.clone());
            user_by_id.insert(user.id, username);
        }

        Ok(user)
    }

    /// Authenticate user with username and password
    pub async fn authenticate_user(&self, username: String, password: String) -> StorageResult<AuthUser> {
        let mut user = {
            let users = self.users.read().await;
            users.get(&username)
                .ok_or_else(|| StorageError::configuration(format!("User {} not found", username)))?
                .clone()
        };

        // Verify password
        let parsed_hash = PasswordHash::new(&user.password_hash)
            .map_err(|e| StorageError::encryption(format!("Invalid password hash: {}", e)))?;

        let argon2 = Argon2::default();
        argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| StorageError::AuthenticationFailed)?;

        // Update last login
        user.update_last_login();
        
        // Store updated user
        {
            let mut users = self.users.write().await;
            users.insert(username, user.clone());
        }

        Ok(user)
    }

    /// Create a new user session
    pub async fn create_session(&self, user_id: Uuid, username: String) -> StorageResult<UserSession> {
        let session = UserSession::new(user_id, username, 24); // 24 hour session

        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(user_id, session.clone());
        }

        Ok(session)
    }

    /// Get active session for user
    pub async fn get_session(&self, user_id: &Uuid) -> StorageResult<UserSession> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(user_id)
            .ok_or_else(|| StorageError::configuration("Session not found".to_string()))?;

        if !session.is_valid() {
            return Err(StorageError::AuthenticationFailed);
        }

        Ok(session.clone())
    }

    /// Invalidate user session
    pub async fn invalidate_session(&self, user_id: &Uuid) -> StorageResult<()> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(user_id);
        Ok(())
    }

    /// Get user by ID
    pub async fn get_user_by_id(&self, user_id: &Uuid) -> StorageResult<AuthUser> {
        let username = {
            let user_by_id = self.user_by_id.read().await;
            user_by_id.get(user_id)
                .ok_or_else(|| StorageError::configuration(format!("User with ID {} not found", user_id)))?
                .clone()
        };

        let users = self.users.read().await;
        users.get(&username)
            .ok_or_else(|| StorageError::configuration(format!("User {} not found", username)))
            .map(|u| u.clone())
    }

    /// Get user by username
    pub async fn get_user_by_username(&self, username: &str) -> StorageResult<AuthUser> {
        let users = self.users.read().await;
        users.get(username)
            .ok_or_else(|| StorageError::configuration(format!("User {} not found", username)))
            .map(|u| u.clone())
    }

    /// Check if user exists
    pub async fn user_exists(&self, username: &str) -> bool {
        let users = self.users.read().await;
        users.contains_key(username)
    }

    /// List all users (for admin purposes)
    pub async fn list_users(&self) -> StorageResult<Vec<AuthUser>> {
        let users = self.users.read().await;
        Ok(users.values().cloned().collect())
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> StorageResult<u64> {
        let mut sessions = self.sessions.write().await;
        let initial_count = sessions.len();
        
        sessions.retain(|_, session| session.is_valid());
        
        let cleaned_count = initial_count - sessions.len();
        Ok(cleaned_count as u64)
    }

    /// Get session count
    pub async fn get_session_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
    }

    /// Get user count
    pub async fn get_user_count(&self) -> usize {
        let users = self.users.read().await;
        users.len()
    }
}

impl Default for AuthStorage {
    fn default() -> Self {
        Self::new()
    }
}
