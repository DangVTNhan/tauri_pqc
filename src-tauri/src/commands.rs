#[tauri::command]
pub fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
pub fn greet_multi_param(name: &str, age: u8) -> String {
    format!("Hello, {}! You are {} years old.", name, age)
}

/// Unmount a WebDAV volume from macOS Finder
/// Unmounts by vault name only
#[tauri::command]
pub async fn unmount_webdav_volume(vault_name: Option<String>) -> Result<(), String> {
    use std::process::Command;

    println!("Attempting to unmount WebDAV volume for vault: {:?}", vault_name);

    #[cfg(target_os = "macos")]
    {
        // Require vault name for unmounting
        let volume_name = vault_name.ok_or_else(|| "Vault name is required for unmounting".to_string())?;

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
                    Ok(())
                } else if stdout.starts_with("error:") {
                    let error_msg = stdout.trim_start_matches("error: ").trim();
                    println!("AppleScript unmount error for {}: {}", volume_name, error_msg);
                    Err(format!("Failed to unmount {}: {}", volume_name, error_msg))
                } else {
                    let error_msg = format!("Unexpected AppleScript output for {}: {}", volume_name, stdout);
                    println!("{}", error_msg);
                    Err(error_msg)
                }
            }
            Err(e) => {
                let error_msg = format!("Failed to execute unmount osascript for {}: {}", volume_name, e);
                println!("{}", error_msg);
                Err(error_msg)
            }
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
pub async fn open_url(url: String, vault_name: Option<String>) -> Result<(), String> {
    use std::process::Command;

    println!("Attempting to mount WebDAV URL in Finder: {}", url);

    #[cfg(target_os = "macos")]
    {
        // First mount the volume
        let mount_script = format!(
            r#"tell application "Finder"
                try
                    mount volume "{}"
                    delay 2
                    return "mounted"
                on error errMsg
                    return "error: " & errMsg
                end try
            end tell"#,
            url
        );

        println!("Executing mount AppleScript: {}", mount_script);

        let mount_output = Command::new("osascript")
            .arg("-e")
            .arg(&mount_script)
            .output();

        match mount_output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);

                println!("Mount AppleScript stdout: {}", stdout);
                if !stderr.is_empty() {
                    println!("Mount AppleScript stderr: {}", stderr);
                }

                if !output.status.success() || stdout.starts_with("error:") {
                    let error_msg = if stdout.starts_with("error:") {
                        stdout.trim_start_matches("error: ").trim()
                    } else {
                        "Failed to mount volume"
                    };
                    println!("Mount failed: {}", error_msg);

                    // Try alternative method using open command
                    println!("Trying alternative method with 'open' command...");
                    let open_result = Command::new("open")
                        .arg(&url)
                        .output();

                    match open_result {
                        Ok(open_output) => {
                            if open_output.status.success() {
                                println!("Successfully opened URL with 'open' command: {}", url);
                                return Ok(());
                            } else {
                                let open_stderr = String::from_utf8_lossy(&open_output.stderr);
                                return Err(format!("Both AppleScript and 'open' command failed. AppleScript error: {}. Open command error: {}", error_msg, open_stderr));
                            }
                        }
                        Err(e) => {
                            return Err(format!("AppleScript failed: {}. Open command also failed: {}", error_msg, e));
                        }
                    }
                }
            }
            Err(e) => {
                println!("Failed to execute mount osascript: {}", e);

                // Try alternative method using open command
                println!("Trying alternative method with 'open' command...");
                let open_result = Command::new("open")
                    .arg(&url)
                    .output();

                match open_result {
                    Ok(open_output) => {
                        if open_output.status.success() {
                            println!("Successfully opened URL with 'open' command: {}", url);
                            return Ok(());
                        } else {
                            let open_stderr = String::from_utf8_lossy(&open_output.stderr);
                            return Err(format!("Both osascript and 'open' command failed. osascript error: {}. Open command error: {}", e, open_stderr));
                        }
                    }
                    Err(open_e) => {
                        return Err(format!("osascript failed: {}. Open command also failed: {}", e, open_e));
                    }
                }
            }
        }

        // First, let's list all available disks to see what's actually mounted
        let list_disks_script = r#"tell application "Finder"
            try
                set diskList to {}
                repeat with aDisk in disks
                    set end of diskList to name of aDisk
                end repeat
                return diskList as string
            on error errMsg
                return "error: " & errMsg
            end try
        end tell"#;

        println!("Listing all available disks...");
        let list_output = Command::new("osascript")
            .arg("-e")
            .arg(list_disks_script)
            .output();

        match list_output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                println!("Available disks: {}", stdout);
            }
            Err(e) => {
                println!("Failed to list disks: {}", e);
            }
        }

        // Try to open the mounted volume using vault name
        if let Some(disk_name) = vault_name {
            println!("Trying to open disk: {}", disk_name);

            let open_script = format!(
                r#"tell application "Finder"
                    try
                        activate
                        open disk "{}"
                        return "success"
                    on error errMsg
                        return "error: " & errMsg
                    end try
                end tell"#,
                disk_name
            );

            println!("Executing open disk AppleScript for: {}", disk_name);

            let open_output = Command::new("osascript")
                .arg("-e")
                .arg(&open_script)
                .output();

            match open_output {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);

                    println!("Open disk AppleScript stdout: {}", stdout);
                    if !stderr.is_empty() {
                        println!("Open disk AppleScript stderr: {}", stderr);
                    }

                    if output.status.success() && stdout.trim() == "success" {
                        println!("Successfully opened disk: {}", disk_name);
                        return Ok(());
                    } else if stdout.starts_with("error:") {
                        let error_msg = stdout.trim_start_matches("error: ").trim();
                        println!("Failed to open disk {}: {}", disk_name, error_msg);
                        return Err(format!("Failed to open disk {}: {}", disk_name, error_msg));
                    } else {
                        let error_msg = format!("Unexpected output for disk {}: {}", disk_name, stdout);
                        println!("{}", error_msg);
                        return Err(error_msg);
                    }
                }
                Err(e) => {
                    let error_msg = format!("Failed to execute AppleScript for disk {}: {}", disk_name, e);
                    println!("{}", error_msg);
                    return Err(error_msg);
                }
            }
        }

        // If no vault name was provided, we can't open the disk
        Err("Vault name is required to open the mounted volume".to_string())
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

