use crate::auth::service::AuthService;
use crate::models::auth::*;
use tauri::{State, AppHandle, Manager};
use std::sync::Arc;
use std::path::PathBuf;
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

    /// Initialize SQLite persistence for the auth service
    pub async fn init_sqlite_persistence(&self, db_path: PathBuf, master_password: &str) -> Result<(), String> {
        let new_service = AuthService::with_sqlite_persistence(db_path, master_password).await?;

        // Replace the service with the persistent one
        {
            let mut service = self.service.write().await;
            *service = new_service;
        }

        Ok(())
    }
}

/// Initialize SQLite persistence for authentication
#[tauri::command]
pub async fn auth_init_persistence(
    app_handle: tauri::AppHandle,
    state: State<'_, AuthState>,
) -> Result<(), String> {
    use tauri::Manager;

    // Get app data directory
    let app_data_dir = app_handle.path().app_data_dir()
        .map_err(|e| format!("Failed to get app data directory: {}", e))?;

    // Create auth database path
    let auth_db_path = app_data_dir.join("auth.db");

    // Use a default master password for auth storage encryption
    let master_password = "auth_storage_master_key_2024";

    state.init_sqlite_persistence(auth_db_path, master_password).await
}

/// Register a new user
#[tauri::command]
pub async fn auth_register(
    username: String,
    password: String,
    app_handle: tauri::AppHandle,
    state: State<'_, AuthState>,
) -> Result<RegisterResponse, String> {
    // Initialize persistence if not already done
    let _ = auth_init_persistence(app_handle, state.clone()).await;

    let service = state.service.read().await;
    service.register_user(username, password).await
}

/// Login user
#[tauri::command]
pub async fn auth_login(
    username: String,
    password: String,
    app_handle: tauri::AppHandle,
    state: State<'_, AuthState>,
) -> Result<LoginResponse, String> {
    // Initialize persistence if not already done
    let _ = auth_init_persistence(app_handle, state.clone()).await;

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
