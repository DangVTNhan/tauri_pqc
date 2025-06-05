use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// User authentication data stored locally
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub salt: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub is_active: bool,
}

impl AuthUser {
    pub fn new(username: String, password_hash: String, salt: Vec<u8>) -> Self {
        Self {
            id: Uuid::new_v4(),
            username,
            password_hash,
            salt,
            created_at: Utc::now(),
            last_login: None,
            is_active: true,
        }
    }

    pub fn update_last_login(&mut self) {
        self.last_login = Some(Utc::now());
    }
}

/// User session data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    pub user_id: Uuid,
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_active: bool,
}

impl UserSession {
    pub fn new(user_id: Uuid, username: String, duration_hours: i64) -> Self {
        let now = Utc::now();
        Self {
            user_id,
            username,
            created_at: now,
            expires_at: now + chrono::Duration::hours(duration_hours),
            is_active: true,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn is_valid(&self) -> bool {
        self.is_active && !self.is_expired()
    }
}

/// Registration request data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}

/// Login request data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Registration response from Go API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub user: ApiUser,
}

/// Login response from Go API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub user: ApiUser,
    pub groups: Option<Vec<ApiGroup>>,
}

/// User data from Go API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiUser {
    pub id: String,
    pub username: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// Group data from Go API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiGroup {
    pub id: String,
    pub name: String,
    pub created_by: String,  // Match Go backend field name
    pub members: Vec<String>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,  // Make optional since Go backend might not always include it
}

/// Public key bundle for API communication (matches Go backend structure)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiPublicKeyBundle {
    pub identity_key: Vec<u8>,
    pub signed_pre_key: Vec<u8>,
    pub kyber_pre_key: Vec<u8>,
    pub one_time_pre_keys: Vec<Vec<u8>>,
    pub signature: Vec<u8>,
}

// REMOVED: ApiPrivateKeyBundle - should NEVER be sent to server
// REMOVED: ApiKeyBundle - should NEVER be sent to server

/// User registration request to Go API
/// SECURITY: Only sends public key bundle - NO private keys or passwords
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiRegisterRequest {
    pub username: String,
    pub public_key_bundle: ApiPublicKeyBundle,
}

/// User login request to Go API
/// SECURITY: Only sends username - NO passwords (authentication done client-side)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiLoginRequest {
    pub username: String,
}

/// Pending message from Go API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingMessage {
    pub id: String,
    pub message_type: String,
    pub sender_id: String,
    pub recipient_id: String,
    pub content: serde_json::Value,
    pub created_at: String,
    pub processed: bool,
}

/// User messages response from Go API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMessagesResponse {
    pub user_id: String,
    pub messages: Vec<PendingMessage>,
    pub count: i32,
}
