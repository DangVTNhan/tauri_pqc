// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
// #[tauri::command]
// fn greet(name: &str) -> String {
//     format!("Hello, {}! You've been greeted from Rust!", name)
// }
use tauri::Manager;

mod commands;
mod models;
mod store;
mod config;
mod vault;
mod webdav;
mod http;
mod auth;

#[cfg(test)]
mod tests;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // Initialize configuration system
            let config_state = config::commands::ConfigState::new(app.handle())
                .expect("Failed to initialize configuration system");
            app.manage(config_state);

            // Initialize WebDAV system
            let webdav_state = webdav::commands::WebDavCommandState::new();
            app.manage(webdav_state);

            // Initialize authentication system
            let auth_state = auth::commands::AuthState::new();
            app.manage(auth_state);

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::greet,
            commands::greet_multi_param,
            commands::mount_webdav_volume,
            commands::unmount_webdav_volume,
            commands::open_url,
            commands::encrypt_data,
            commands::decrypt_data,
            commands::generate_key_bundle,
            commands::perform_key_exchange,
            commands::wrap_master_key,
            commands::unwrap_master_key,
            commands::decrypt_private_key,
            // New cryptographic commands
            commands::generate_ephemeral_keypair,
            commands::generate_kyber_keypair,
            commands::perform_ecdh,
            commands::kyber_encapsulate,
            commands::kyber_decapsulate,
            commands::derive_shared_secret,
            commands::generate_random_bytes,
            // API proxy commands
            commands::api_health_check,
            commands::api_upload_blob,
            commands::api_download_blob,
            commands::api_create_group,
            commands::api_get_group,
            commands::api_add_group_member,
            commands::api_get_public_key_bundles,
            commands::api_send_bulk_wrapped_keys,
            commands::api_share_file_metadata,
            commands::api_get_group_files,
            commands::api_get_user_by_username,
            commands::api_get_user_messages,
            commands::api_mark_message_processed,
            // E2EE file sharing commands
            commands::e2ee_share_file_with_group,
            commands::e2ee_download_and_decrypt_file,
            commands::get_user_private_keys,
            // Authentication commands
            auth::commands::auth_init_persistence,
            auth::commands::auth_register,
            auth::commands::auth_login,
            auth::commands::auth_logout,
            auth::commands::auth_is_logged_in,
            auth::commands::auth_get_current_session,
            auth::commands::auth_get_current_user,
            auth::commands::auth_cleanup_sessions,
            // Configuration commands
            config::commands::load_config,
            config::commands::save_config,
            config::commands::get_app_data_dir,
            config::commands::get_config_path,
            config::commands::add_vault,
            config::commands::remove_vault,
            config::commands::update_window_config,
            config::commands::update_preferences,
            config::commands::backup_config,
            config::commands::restore_config_from_backup,
            config::commands::reset_config_to_defaults,
            config::commands::validate_config,
            config::commands::ensure_directories,
            config::commands::init_config_system,
            // Vault commands
            vault::commands::create_vault,
            vault::commands::verify_vault_password,
            vault::commands::load_vault_metadata,
            vault::commands::is_valid_vault,
            // WebDAV commands
            webdav::commands::unlock_vault,
            webdav::commands::lock_vault,
            webdav::commands::get_vault_statuses,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
