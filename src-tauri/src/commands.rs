#[tauri::command]
pub fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
pub fn greet_multi_param(name: &str, age: u8) -> String {
    format!("Hello, {}! You are {} years old.", name, age)
}

/// Unmount a WebDAV volume from macOS Finder
/// Attempts to unmount both by vault name and by IP address (127.0.0.1)
#[tauri::command]
pub async fn unmount_webdav_volume(vault_name: Option<String>) -> Result<(), String> {
    use std::process::Command;

    println!("Attempting to unmount WebDAV volume for vault: {:?}", vault_name);

    #[cfg(target_os = "macos")]
    {
        // Try to unmount by vault name first (if provided), then by IP address
        let volume_names = if let Some(name) = vault_name {
            vec![name, "127.0.0.1".to_string()]
        } else {
            vec!["127.0.0.1".to_string()]
        };

        let mut last_error = None;
        let mut unmounted_any = false;

        for volume_name in volume_names {
            println!("Trying to unmount volume: {}", volume_name);

            let script = format!(
                r#"tell application "Finder"
                    try
                        eject disk "{}"
                        return "success"
                    on error errMsg
                        return "error: " & errMsg
                    end try
                end tell"#,
                volume_name
            );

            println!("Executing unmount AppleScript for volume: {}", volume_name);

            let output = Command::new("osascript")
                .arg("-e")
                .arg(&script)
                .output();

            match output {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);

                    println!("Unmount AppleScript stdout for {}: {}", volume_name, stdout);
                    if !stderr.is_empty() {
                        println!("Unmount AppleScript stderr for {}: {}", volume_name, stderr);
                    }

                    if output.status.success() && stdout.trim() == "success" {
                        println!("Successfully unmounted volume: {}", volume_name);
                        unmounted_any = true;
                    } else if stdout.starts_with("error:") {
                        let error_msg = stdout.trim_start_matches("error: ").trim();
                        println!("AppleScript unmount error for {}: {}", volume_name, error_msg);
                        last_error = Some(format!("Failed to unmount {}: {}", volume_name, error_msg));
                    } else {
                        let error_msg = format!("Unexpected AppleScript output for {}: {}", volume_name, stdout);
                        println!("{}", error_msg);
                        last_error = Some(error_msg);
                    }
                }
                Err(e) => {
                    let error_msg = format!("Failed to execute unmount osascript for {}: {}", volume_name, e);
                    println!("{}", error_msg);
                    last_error = Some(error_msg);
                }
            }
        }

        if unmounted_any {
            println!("Successfully unmounted at least one volume");
            Ok(())
        } else if let Some(error) = last_error {
            Err(error)
        } else {
            Err("No volumes found to unmount".to_string())
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        println!("Volume unmounting is only supported on macOS");
        Ok(()) // Don't fail on other platforms
    }
}

/// Open a WebDAV URL in Finder (mount as network drive)
#[tauri::command]
pub async fn open_url(url: String) -> Result<(), String> {
    use std::process::Command;

    println!("Attempting to mount WebDAV URL in Finder: {}", url);

    #[cfg(target_os = "macos")]
    {
        // First try using osascript with better error handling
        let script = format!(
            r#"tell application "Finder"
                try
                    mount volume "{}"
                    activate
                    delay 2
                    -- Open the mounted volume directly
                    open disk "127.0.0.1"
                    return "success"
                on error errMsg
                    return "error: " & errMsg
                end try
            end tell"#,
            url
        );

        println!("Executing AppleScript: {}", script);

        let output = Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .output();

        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);

                println!("AppleScript stdout: {}", stdout);
                if !stderr.is_empty() {
                    println!("AppleScript stderr: {}", stderr);
                }

                if output.status.success() && stdout.trim() == "success" {
                    println!("Successfully mounted WebDAV URL: {}", url);
                    Ok(())
                } else if stdout.starts_with("error:") {
                    let error_msg = stdout.trim_start_matches("error: ").trim();
                    println!("AppleScript error: {}", error_msg);

                    // Try alternative method using open command
                    println!("Trying alternative method with 'open' command...");
                    let open_result = Command::new("open")
                        .arg(&url)
                        .output();

                    match open_result {
                        Ok(open_output) => {
                            if open_output.status.success() {
                                println!("Successfully opened URL with 'open' command: {}", url);
                                Ok(())
                            } else {
                                let open_stderr = String::from_utf8_lossy(&open_output.stderr);
                                Err(format!("Both AppleScript and 'open' command failed. AppleScript error: {}. Open command error: {}", error_msg, open_stderr))
                            }
                        }
                        Err(e) => {
                            Err(format!("AppleScript failed: {}. Open command also failed: {}", error_msg, e))
                        }
                    }
                } else {
                    Err(format!("Unexpected AppleScript output: {}", stdout))
                }
            }
            Err(e) => {
                println!("Failed to execute osascript: {}", e);

                // Try alternative method using open command
                println!("Trying alternative method with 'open' command...");
                let open_result = Command::new("open")
                    .arg(&url)
                    .output();

                match open_result {
                    Ok(open_output) => {
                        if open_output.status.success() {
                            println!("Successfully opened URL with 'open' command: {}", url);
                            Ok(())
                        } else {
                            let open_stderr = String::from_utf8_lossy(&open_output.stderr);
                            Err(format!("Both osascript and 'open' command failed. osascript error: {}. Open command error: {}", e, open_stderr))
                        }
                    }
                    Err(open_e) => {
                        Err(format!("osascript failed: {}. Open command also failed: {}", e, open_e))
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let result = Command::new("cmd")
            .args(["/C", "start", &url])
            .spawn();

        match result {
            Ok(_) => {
                println!("Successfully launched 'start' command for URL: {}", url);
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Failed to open URL on Windows: {}", e);
                eprintln!("{}", error_msg);
                Err(error_msg)
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let result = Command::new("xdg-open")
            .arg(&url)
            .spawn();

        match result {
            Ok(_) => {
                println!("Successfully launched 'xdg-open' command for URL: {}", url);
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Failed to open URL on Linux: {}", e);
                eprintln!("{}", error_msg);
                Err(error_msg)
            }
        }
    }
}

