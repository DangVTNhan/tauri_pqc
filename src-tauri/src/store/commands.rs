use tauri::State;
use std::sync::Arc;
use uuid::Uuid;

use crate::models::{User, Group, SharedFile, AppResult};
use super::{
    Storage, Transaction, StorageManager, StorageStatistics, QueryOptions,
    StorageConfig, StorageBackend, EncryptionService,
};

/// Application state containing the storage manager
pub struct AppState {
    pub storage_manager: Arc<StorageManager>,
}

/// Initialize storage with configuration
#[tauri::command]
pub async fn init_storage(
    config_path: Option<String>,
    password: Option<String>,
) -> AppResult<String> {
    let config = if let Some(path) = config_path {
        StorageConfig::load_from_file(path)
            .map_err(|e| crate::models::AppError::InternalError(e.to_string()))?
    } else {
        StorageConfig::default()
    };

    let storage_manager = if let Some(pwd) = password {
        let salt = EncryptionService::generate_salt();
        StorageManager::with_password(config, &pwd, &salt).await
            .map_err(|e| crate::models::AppError::InternalError(e.to_string()))?
    } else {
        StorageManager::new(config).await
            .map_err(|e| crate::models::AppError::InternalError(e.to_string()))?
    };

    Ok("Storage initialized successfully".to_string())
}

/// Get storage health status
#[tauri::command]
pub async fn storage_health_check(
    state: State<'_, AppState>,
) -> AppResult<String> {
    state.storage_manager.health_check().await
        .map_err(|e| crate::models::AppError::InternalError(e.to_string()))?;

    Ok("Storage is healthy".to_string())
}

/// Get storage statistics
#[tauri::command]
pub async fn get_storage_statistics(
    state: State<'_, AppState>,
) -> AppResult<StorageStatistics> {
    let (primary_stats, _) = state.storage_manager.get_all_statistics().await
        .map_err(|e| crate::models::AppError::InternalError(e.to_string()))?;

    Ok(primary_stats)
}

// User management commands

/// Create a new user
#[tauri::command]
pub async fn create_user(
    state: State<'_, AppState>,
    user: User,
) -> AppResult<String> {
    state.storage_manager.primary().create_user(&user).await
        .map_err(|e| crate::models::AppError::from(e))?;

    Ok(format!("User {} created successfully", user.name))
}

/// Get user by ID
#[tauri::command]
pub async fn get_user(
    state: State<'_, AppState>,
    user_id: String,
) -> AppResult<User> {
    let uuid = Uuid::parse_str(&user_id)
        .map_err(|e| crate::models::AppError::InternalError(format!("Invalid UUID: {}", e)))?;

    let user = state.storage_manager.primary().get_user(&uuid).await
        .map_err(|e| crate::models::AppError::from(e))?;

    Ok(user)
}

/// Update an existing user
#[tauri::command]
pub async fn update_user(
    state: State<'_, AppState>,
    user: User,
) -> AppResult<String> {
    state.storage_manager.primary().update_user(&user).await
        .map_err(|e| crate::models::AppError::from(e))?;

    Ok(format!("User {} updated successfully", user.name))
}

/// Delete a user
#[tauri::command]
pub async fn delete_user(
    state: State<'_, AppState>,
    user_id: String,
) -> AppResult<String> {
    let uuid = Uuid::parse_str(&user_id)
        .map_err(|e| crate::models::AppError::InternalError(format!("Invalid UUID: {}", e)))?;

    state.storage_manager.primary().delete_user(&uuid).await
        .map_err(|e| crate::models::AppError::from(e))?;

    Ok("User deleted successfully".to_string())
}

/// List all users
#[tauri::command]
pub async fn list_users(
    state: State<'_, AppState>,
) -> AppResult<Vec<User>> {
    let users = state.storage_manager.primary().list_users().await
        .map_err(|e| crate::models::AppError::from(e))?;

    Ok(users)
}

/// Search users by name
#[tauri::command]
pub async fn search_users(
    state: State<'_, AppState>,
    pattern: String,
) -> AppResult<Vec<User>> {
    let users = state.storage_manager.primary().find_users_by_name(&pattern).await
        .map_err(|e| crate::models::AppError::from(e))?;

    Ok(users)
}

// Group management commands

/// Create a new group
#[tauri::command]
pub async fn create_group(
    state: State<'_, AppState>,
    group: Group,
) -> AppResult<String> {
    state.storage_manager.primary().create_group(&group).await
        .map_err(|e| crate::models::AppError::from(e))?;

    Ok(format!("Group {} created successfully", group.name))
}

/// Get group by ID
#[tauri::command]
pub async fn get_group(
    state: State<'_, AppState>,
    group_id: String,
) -> AppResult<Group> {
    let uuid = Uuid::parse_str(&group_id)
        .map_err(|e| crate::models::AppError::InternalError(format!("Invalid UUID: {}", e)))?;

    let group = state.storage_manager.primary().get_group(&uuid).await
        .map_err(|e| crate::models::AppError::from(e))?;

    Ok(group)
}

/// Update an existing group
#[tauri::command]
pub async fn update_group(
    state: State<'_, AppState>,
    group: Group,
) -> AppResult<String> {
    state.storage_manager.primary().update_group(&group).await
        .map_err(|e| crate::models::AppError::from(e))?;

    Ok(format!("Group {} updated successfully", group.name))
}

/// Delete a group
#[tauri::command]
pub async fn delete_group(
    state: State<'_, AppState>,
    group_id: String,
) -> AppResult<String> {
    let uuid = Uuid::parse_str(&group_id)
        .map_err(|e| crate::models::AppError::InternalError(format!("Invalid UUID: {}", e)))?;

    state.storage_manager.primary().delete_group(&uuid).await
        .map_err(|e| crate::models::AppError::from(e))?;

    Ok("Group deleted successfully".to_string())
}

/// List all groups
#[tauri::command]
pub async fn list_groups(
    state: State<'_, AppState>,
) -> AppResult<Vec<Group>> {
    let groups = state.storage_manager.primary().list_groups().await
        .map_err(|e| crate::models::AppError::from(e))?;

    Ok(groups)
}

/// Get groups for a user
#[tauri::command]
pub async fn get_user_groups(
    state: State<'_, AppState>,
    user_id: String,
) -> AppResult<Vec<Group>> {
    let uuid = Uuid::parse_str(&user_id)
        .map_err(|e| crate::models::AppError::InternalError(format!("Invalid UUID: {}", e)))?;

    let groups = state.storage_manager.primary().get_user_groups(&uuid).await
        .map_err(|e| crate::models::AppError::from(e))?;

    Ok(groups)
}

/// Add member to group
#[tauri::command]
pub async fn add_group_member(
    state: State<'_, AppState>,
    group_id: String,
    user_id: String,
) -> AppResult<String> {
    let group_uuid = Uuid::parse_str(&group_id)
        .map_err(|e| crate::models::AppError::InternalError(format!("Invalid group UUID: {}", e)))?;
    let user_uuid = Uuid::parse_str(&user_id)
        .map_err(|e| crate::models::AppError::InternalError(format!("Invalid user UUID: {}", e)))?;

    state.storage_manager.primary().add_group_member(&group_uuid, &user_uuid).await
        .map_err(|e| crate::models::AppError::from(e))?;

    Ok("Member added to group successfully".to_string())
}

/// Remove member from group
#[tauri::command]
pub async fn remove_group_member(
    state: State<'_, AppState>,
    group_id: String,
    user_id: String,
) -> AppResult<String> {
    let group_uuid = Uuid::parse_str(&group_id)
        .map_err(|e| crate::models::AppError::InternalError(format!("Invalid group UUID: {}", e)))?;
    let user_uuid = Uuid::parse_str(&user_id)
        .map_err(|e| crate::models::AppError::InternalError(format!("Invalid user UUID: {}", e)))?;

    state.storage_manager.primary().remove_group_member(&group_uuid, &user_uuid).await
        .map_err(|e| crate::models::AppError::from(e))?;

    Ok("Member removed from group successfully".to_string())
}

// File management commands

/// Create a new shared file
#[tauri::command]
pub async fn create_shared_file(
    state: State<'_, AppState>,
    file: SharedFile,
) -> AppResult<String> {
    state.storage_manager.primary().create_shared_file(&file).await
        .map_err(|e| crate::models::AppError::from(e))?;

    Ok(format!("File {} shared successfully", file.original_name))
}

/// Get shared file by ID
#[tauri::command]
pub async fn get_shared_file(
    state: State<'_, AppState>,
    file_id: String,
) -> AppResult<SharedFile> {
    let uuid = Uuid::parse_str(&file_id)
        .map_err(|e| crate::models::AppError::InternalError(format!("Invalid UUID: {}", e)))?;

    let file = state.storage_manager.primary().get_shared_file(&uuid).await
        .map_err(|e| crate::models::AppError::from(e))?;

    Ok(file)
}

/// List all shared files
#[tauri::command]
pub async fn list_shared_files(
    state: State<'_, AppState>,
) -> AppResult<Vec<SharedFile>> {
    let files = state.storage_manager.primary().list_shared_files().await
        .map_err(|e| crate::models::AppError::from(e))?;

    Ok(files)
}

/// Get files for a group
#[tauri::command]
pub async fn get_group_files(
    state: State<'_, AppState>,
    group_id: String,
) -> AppResult<Vec<SharedFile>> {
    let uuid = Uuid::parse_str(&group_id)
        .map_err(|e| crate::models::AppError::InternalError(format!("Invalid UUID: {}", e)))?;

    let files = state.storage_manager.primary().get_group_files(&uuid).await
        .map_err(|e| crate::models::AppError::from(e))?;

    Ok(files)
}

/// Mark file as downloaded by user
#[tauri::command]
pub async fn mark_file_downloaded(
    state: State<'_, AppState>,
    file_id: String,
    user_id: String,
) -> AppResult<String> {
    let file_uuid = Uuid::parse_str(&file_id)
        .map_err(|e| crate::models::AppError::InternalError(format!("Invalid file UUID: {}", e)))?;
    let user_uuid = Uuid::parse_str(&user_id)
        .map_err(|e| crate::models::AppError::InternalError(format!("Invalid user UUID: {}", e)))?;

    state.storage_manager.primary().mark_file_downloaded(&file_uuid, &user_uuid).await
        .map_err(|e| crate::models::AppError::from(e))?;

    Ok("File marked as downloaded".to_string())
}

// Utility commands

/// Initialize storage with demo data
#[tauri::command]
pub async fn init_demo_data(
    state: State<'_, AppState>,
) -> AppResult<String> {
    crate::store::utils::init_with_demo_data(state.storage_manager.primary()).await
        .map_err(|e| crate::models::AppError::InternalError(e.to_string()))?;

    Ok("Demo data initialized successfully".to_string())
}

/// Backup storage to file
#[tauri::command]
pub async fn backup_storage(
    state: State<'_, AppState>,
    file_path: String,
) -> AppResult<String> {
    state.storage_manager.backup_to_file(&file_path).await
        .map_err(|e| crate::models::AppError::InternalError(e.to_string()))?;

    Ok(format!("Storage backed up to {}", file_path))
}

/// Restore storage from file
#[tauri::command]
pub async fn restore_storage(
    state: State<'_, AppState>,
    file_path: String,
) -> AppResult<String> {
    state.storage_manager.restore_from_file(&file_path).await
        .map_err(|e| crate::models::AppError::InternalError(e.to_string()))?;

    Ok(format!("Storage restored from {}", file_path))
}

/// Cleanup expired data
#[tauri::command]
pub async fn cleanup_storage(
    state: State<'_, AppState>,
) -> AppResult<String> {
    let (cleaned, _) = state.storage_manager.cleanup_all().await
        .map_err(|e| crate::models::AppError::InternalError(e.to_string()))?;

    Ok(format!("Cleaned up {} expired records", cleaned))
}

/// Optimize storage
#[tauri::command]
pub async fn optimize_storage(
    state: State<'_, AppState>,
) -> AppResult<String> {
    state.storage_manager.optimize_all().await
        .map_err(|e| crate::models::AppError::InternalError(e.to_string()))?;

    Ok("Storage optimized successfully".to_string())
}
