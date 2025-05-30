#[tauri::command]
pub fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
pub fn greet_multi_param(name: &str, age: u8) -> String {
    format!("Hello, {}! You are {} years old.", name, age)
}

