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

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::greet,
            commands::greet_multi_param,
            // Configuration commands
            config::commands::load_config,
            config::commands::save_config,
            config::commands::get_app_data_dir,
            config::commands::get_config_path,
            config::commands::add_vault,
            config::commands::remove_vault,
            config::commands::set_active_vault,
            config::commands::get_active_vault,
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
