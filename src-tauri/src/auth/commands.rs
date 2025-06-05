use crate::auth::service::AuthService;
use crate::models::auth::*;
use tauri::State;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Authentication state for Tauri commands
#[derive(Clone)]
pub struct AuthState {
    pub service: Arc<RwLock<AuthService>>,
}

impl AuthState {
    pub fn new() -> Self {
        Self {
            service: Arc::new(RwLock::new(AuthService::new())),
        }
    }
}

/// Register a new user
#[tauri::command]
pub async fn auth_register(
    username: String,
    password: String,
    state: State<'_, AuthState>,
) -> Result<RegisterResponse, String> {
    let service = state.service.read().await;
    service.register_user(username, password).await
}

/// Login user
#[tauri::command]
pub async fn auth_login(
    username: String,
    password: String,
    state: State<'_, AuthState>,
) -> Result<LoginResponse, String> {
    let service = state.service.read().await;
    service.login_user(username, password).await
}

/// Logout current user
#[tauri::command]
pub async fn auth_logout(state: State<'_, AuthState>) -> Result<(), String> {
    let service = state.service.read().await;
    service.logout().await
}

/// Check if user is logged in
#[tauri::command]
pub async fn auth_is_logged_in(state: State<'_, AuthState>) -> Result<bool, String> {
    let service = state.service.read().await;
    Ok(service.is_logged_in().await)
}

/// Get current user session
#[tauri::command]
pub async fn auth_get_current_session(state: State<'_, AuthState>) -> Result<Option<UserSession>, String> {
    let service = state.service.read().await;
    Ok(service.get_current_session().await)
}

/// Get current user
#[tauri::command]
pub async fn auth_get_current_user(state: State<'_, AuthState>) -> Result<AuthUser, String> {
    let service = state.service.read().await;
    service.get_current_user().await
}

/// Clean up expired sessions
#[tauri::command]
pub async fn auth_cleanup_sessions(state: State<'_, AuthState>) -> Result<u64, String> {
    let service = state.service.read().await;
    service.cleanup_expired_sessions().await
}
