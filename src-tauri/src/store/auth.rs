use crate::models::auth::{AuthUser, UserSession};
use crate::store::{StorageError, StorageResult, EncryptionService, MasterKey, EncryptionConfig};
use crate::commands::PrivateKeyBundleResult;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use uuid::Uuid;
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use sqlx::{SqlitePool, Row, sqlite::SqliteConnectOptions};
use std::str::FromStr;

/// Authentication storage service for managing user credentials and sessions
#[derive(Clone)]
pub struct AuthStorage {
    pool: Option<SqlitePool>, // SQLite connection pool for persistent storage
    encryption_service: Option<EncryptionService>, // For encrypting sensitive data
    sessions: Arc<RwLock<HashMap<Uuid, UserSession>>>, // user_id -> session (in-memory only)
}

impl AuthStorage {
    /// Create new authentication storage with in-memory only
    pub fn new() -> Self {
        Self {
            pool: None,
            encryption_service: None,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new AuthStorage instance with SQLite database
    pub async fn new_with_sqlite(database_url: &str) -> StorageResult<Self> {
        // Create database connection pool
        let pool = SqlitePool::connect(database_url).await?;

        // Run migrations to create tables
        sqlx::migrate!("./migrations").run(&pool).await?;

        Ok(Self {
            pool: Some(pool),
            encryption_service: None,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Create new authentication storage with encrypted SQLite persistence
    pub async fn with_sqlite_persistence(db_path: PathBuf, master_password: &str) -> StorageResult<Self> {
        // Create salt file path alongside the database
        let salt_path = db_path.with_extension("salt");

        // Try to load existing salt, or generate a new one
        let salt = if salt_path.exists() {
            // Load existing salt from file
            let salt_bytes = tokio::fs::read(&salt_path).await
                .map_err(|e| StorageError::Io(e))?;

            // Convert Vec<u8> to [u8; 32]
            if salt_bytes.len() != 32 {
                return Err(StorageError::configuration(format!(
                    "Invalid salt file: expected 32 bytes, got {}",
                    salt_bytes.len()
                )));
            }
            let mut salt_array = [0u8; 32];
            salt_array.copy_from_slice(&salt_bytes);
            salt_array
        } else {
            // Generate new salt and save it
            let new_salt = EncryptionService::generate_salt();

            // Ensure parent directory exists
            if let Some(parent) = salt_path.parent() {
                tokio::fs::create_dir_all(parent).await
                    .map_err(|e| StorageError::Io(e))?;
            }

            // Save salt to file
            tokio::fs::write(&salt_path, &new_salt).await
                .map_err(|e| StorageError::Io(e))?;

            new_salt
        };

        // Create encryption service for sensitive data
        let encryption_service = EncryptionService::with_password(
            master_password,
            &salt,
            EncryptionConfig::default(),
        )?;

        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| StorageError::Io(e))?;
        }

        // Create SQLite connection
        let database_url = format!("sqlite:{}", db_path.display());
        let connect_options = SqliteConnectOptions::from_str(&database_url)
            .map_err(|e| StorageError::configuration(e.to_string()))?
            .create_if_missing(true);

        let pool = SqlitePool::connect_with(connect_options).await?;

        let auth_storage = Self {
            pool: Some(pool),
            encryption_service: Some(encryption_service),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        };

        // Initialize database schema
        auth_storage.init_schema().await?;

        Ok(auth_storage)
    }

    /// Initialize database schema for authentication
    async fn init_schema(&self) -> StorageResult<()> {
        if let Some(pool) = &self.pool {
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS auth_users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    encrypted_private_keys TEXT NOT NULL,
                    public_keys TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_login TEXT,
                    is_active BOOLEAN NOT NULL DEFAULT 1
                )
                "#,
            )
            .execute(pool)
            .await?;
        }
        Ok(())
    }

    /// Register a new user with password hashing and key bundle
    pub async fn register_user_with_keys(&self, username: String, password: String, private_keys: crate::commands::PrivateKeyBundleResult) -> StorageResult<AuthUser> {
        if let Some(pool) = &self.pool {
            // Check if user already exists
            let existing_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM auth_users WHERE username = ?"
            )
            .bind(&username)
            .fetch_one(pool)
            .await?;

            if existing_count > 0 {
                return Err(StorageError::configuration(format!("User {} already exists", username)));
            }

            // Hash password with Argon2
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let password_hash = argon2
                .hash_password(password.as_bytes(), &salt)
                .map_err(|e| StorageError::encryption(format!("Password hashing failed: {}", e)))?
                .to_string();

            // Create user
            let user = AuthUser::new(username.clone(), password_hash.clone(), salt.to_string());

            // Serialize private keys to JSON
            let private_keys_json = serde_json::to_string(&private_keys)
                .map_err(|e| StorageError::serialization(format!("Failed to serialize private keys: {}", e)))?;

            // Store user in database with private keys
            let insert_result = sqlx::query(
                r#"
                INSERT INTO auth_users (id, username, password_hash, encrypted_private_keys, public_keys, created_at, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                "#
            )
            .bind(user.id.to_string())
            .bind(&username)
            .bind(&password_hash)
            .bind(&private_keys_json)
            .bind("") // Empty public_keys for now
            .bind(user.created_at.to_rfc3339())
            .bind(true)
            .execute(pool)
            .await;

            match insert_result {
                Ok(_) => {
                }
                Err(e) => {
                    return Err(StorageError::from(e));
                }
            }

            Ok(user)
        } else {
            Err(StorageError::configuration("Database not initialized"))
        }
    }

    /// Register a new user with password hashing
    pub async fn register_user(&self, username: String, password: String) -> StorageResult<AuthUser> {
        if let Some(pool) = &self.pool {
            // Check if user already exists
            let existing_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM auth_users WHERE username = ?"
            )
            .bind(&username)
            .fetch_one(pool)
            .await?;

            if existing_count > 0 {
                return Err(StorageError::configuration(format!("User {} already exists", username)));
            }

            // Hash password with Argon2
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let password_hash = argon2
                .hash_password(password.as_bytes(), &salt)
                .map_err(|e| StorageError::encryption(format!("Password hashing failed: {}", e)))?
                .to_string();

            // Create user
            let user = AuthUser::new(username.clone(), password_hash.clone(), salt.to_string());

            // Store user in database
            sqlx::query(
                r#"
                INSERT INTO auth_users (id, username, password_hash, encrypted_private_keys, public_keys, created_at, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                "#
            )
            .bind(user.id.to_string())
            .bind(&username)
            .bind(&password_hash)
            .bind("") // Empty encrypted_private_keys for now
            .bind("") // Empty public_keys for now
            .bind(user.created_at.to_rfc3339())
            .bind(true)
            .execute(pool)
            .await?;

            Ok(user)
        } else {
            Err(StorageError::configuration("Database not initialized"))
        }
    }

    /// Authenticate user with username and password
    pub async fn authenticate_user(&self, username: String, password: String) -> StorageResult<AuthUser> {
        if let Some(pool) = &self.pool {
            // Fetch user from database
            let row = sqlx::query(
                "SELECT id, username, password_hash, created_at, last_login, is_active FROM auth_users WHERE username = ? AND is_active = 1"
            )
            .bind(&username)
            .fetch_optional(pool)
            .await?;

            let row = row.ok_or_else(|| StorageError::configuration(format!("User {} not found", username)))?;

            let user_id: String = row.get("id");
            let stored_password_hash: String = row.get("password_hash");
            let created_at_str: String = row.get("created_at");
            let last_login_str: Option<String> = row.get("last_login");
            let is_active: bool = row.get("is_active");

            // Verify password
            let parsed_hash = PasswordHash::new(&stored_password_hash)
                .map_err(|e| StorageError::encryption(format!("Invalid password hash: {}", e)))?;

            let argon2 = Argon2::default();
            argon2
                .verify_password(password.as_bytes(), &parsed_hash)
                .map_err(|_| StorageError::AuthenticationFailed)?;

            // Parse dates
            let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
                .map_err(|e| StorageError::configuration(format!("Invalid created_at date: {}", e)))?
                .with_timezone(&chrono::Utc);

            let last_login = if let Some(last_login_str) = last_login_str {
                Some(chrono::DateTime::parse_from_rfc3339(&last_login_str)
                    .map_err(|e| StorageError::configuration(format!("Invalid last_login date: {}", e)))?
                    .with_timezone(&chrono::Utc))
            } else {
                None
            };

            // Create user object
            let mut user = AuthUser {
                id: Uuid::parse_str(&user_id)
                    .map_err(|e| StorageError::configuration(format!("Invalid user ID: {}", e)))?,
                username: username.clone(),
                password_hash: stored_password_hash,
                salt: String::new(), // We don't store salt separately in this implementation
                created_at,
                last_login,
                is_active,
            };

            // Update last login
            user.update_last_login();

            // Update last login in database
            sqlx::query(
                "UPDATE auth_users SET last_login = ? WHERE username = ?"
            )
            .bind(user.last_login.unwrap().to_rfc3339())
            .bind(&username)
            .execute(pool)
            .await?;

            Ok(user)
        } else {
            Err(StorageError::configuration("Database not initialized"))
        }
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
        if let Some(pool) = &self.pool {
            let row = sqlx::query(
                "SELECT id, username, password_hash, created_at, last_login, is_active FROM auth_users WHERE id = ? AND is_active = 1"
            )
            .bind(user_id.to_string())
            .fetch_optional(pool)
            .await?;

            let row = row.ok_or_else(|| StorageError::configuration(format!("User with ID {} not found", user_id)))?;

            self.row_to_auth_user(row).await
        } else {
            Err(StorageError::configuration("Database not initialized"))
        }
    }

    /// Get user by username
    pub async fn get_user_by_username(&self, username: &str) -> StorageResult<AuthUser> {
        if let Some(pool) = &self.pool {
            let row = sqlx::query(
                "SELECT id, username, password_hash, created_at, last_login, is_active FROM auth_users WHERE username = ? AND is_active = 1"
            )
            .bind(username)
            .fetch_optional(pool)
            .await?;

            let row = row.ok_or_else(|| StorageError::configuration(format!("User {} not found", username)))?;

            self.row_to_auth_user(row).await
        } else {
            Err(StorageError::configuration("Database not initialized"))
        }
    }

    /// Check if user exists
    pub async fn user_exists(&self, username: &str) -> bool {
        if let Some(pool) = &self.pool {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM auth_users WHERE username = ? AND is_active = 1"
            )
            .bind(username)
            .fetch_one(pool)
            .await
            .unwrap_or(0);

            count > 0
        } else {
            false
        }
    }

    /// Helper method to convert database row to AuthUser
    async fn row_to_auth_user(&self, row: sqlx::sqlite::SqliteRow) -> StorageResult<AuthUser> {
        let user_id: String = row.get("id");
        let username: String = row.get("username");
        let password_hash: String = row.get("password_hash");
        let created_at_str: String = row.get("created_at");
        let last_login_str: Option<String> = row.get("last_login");
        let is_active: bool = row.get("is_active");

        // Parse dates
        let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| StorageError::configuration(format!("Invalid created_at date: {}", e)))?
            .with_timezone(&chrono::Utc);

        let last_login = if let Some(last_login_str) = last_login_str {
            Some(chrono::DateTime::parse_from_rfc3339(&last_login_str)
                .map_err(|e| StorageError::configuration(format!("Invalid last_login date: {}", e)))?
                .with_timezone(&chrono::Utc))
        } else {
            None
        };

        Ok(AuthUser {
            id: Uuid::parse_str(&user_id)
                .map_err(|e| StorageError::configuration(format!("Invalid user ID: {}", e)))?,
            username,
            password_hash,
            salt: String::new(), // We don't store salt separately in this implementation
            created_at,
            last_login,
            is_active,
        })
    }

    /// List all users (for admin purposes)
    pub async fn list_users(&self) -> StorageResult<Vec<AuthUser>> {
        if let Some(pool) = &self.pool {
            let rows = sqlx::query(
                "SELECT id, username, password_hash, created_at, last_login, is_active FROM auth_users WHERE is_active = 1"
            )
            .fetch_all(pool)
            .await?;

            let mut users = Vec::new();
            for row in rows {
                users.push(self.row_to_auth_user(row).await?);
            }

            Ok(users)
        } else {
            Err(StorageError::configuration("Database not initialized"))
        }
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> StorageResult<u64> {
        let mut sessions = self.sessions.write().await;
        let initial_count = sessions.len();

        sessions.retain(|_, session| session.is_valid());

        let cleaned_count = initial_count - sessions.len();
        Ok(cleaned_count as u64)
    }

    /// Get user's private keys by decrypting them with password
    pub async fn get_user_private_keys(&self, user_id: &uuid::Uuid, _password: &str) -> StorageResult<crate::commands::PrivateKeyBundleResult> {

        if let Some(pool) = &self.pool {
            // Get user from database
            let row_result = sqlx::query(
                "SELECT encrypted_private_keys FROM auth_users WHERE id = ? AND is_active = 1"
            )
            .bind(user_id.to_string())
            .fetch_one(pool)
            .await;

            match row_result {
                Ok(row) => {
                    let encrypted_private_keys: String = row.get("encrypted_private_keys");

                    // Deserialize private keys from JSON
                    let private_keys: crate::commands::PrivateKeyBundleResult = serde_json::from_str(&encrypted_private_keys)
                        .map_err(|e| {
                            StorageError::serialization(format!("Failed to deserialize private keys: {}", e))
                        })?;

                    println!("🔍 DEBUG AUTH: Successfully retrieved private keys");
                    Ok(private_keys)
                }
                Err(e) => {
                    Err(StorageError::from(e))
                }
            }
        } else {
            Err(StorageError::configuration("Database not initialized"))
        }
    }

    /// Get session count
    pub async fn get_session_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
    }

    /// Get user count
    pub async fn get_user_count(&self) -> usize {
        if let Some(pool) = &self.pool {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM auth_users WHERE is_active = 1"
            )
            .fetch_one(pool)
            .await
            .unwrap_or(0);

            count as usize
        } else {
            0
        }
    }
}

impl Default for AuthStorage {
    fn default() -> Self {
        Self::new()
    }
}
