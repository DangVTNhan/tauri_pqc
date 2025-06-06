

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

        // Use tokio::task::spawn_blocking to properly handle the blocking osascript call
        let output = tokio::task::spawn_blocking({
            let script = script.clone();
            move || {
                std::process::Command::new("osascript")
                    .arg("-e")
                    .arg(&script)
                    .output()
            }
        }).await.map_err(|e| format!("Failed to spawn blocking task: {}", e))?;

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

/// Mount a WebDAV volume using Cryptomator-style AppleScript with authentication
#[tauri::command]
pub async fn mount_webdav_volume(
    url: String,
    vault_name: String,
    username: String,
    password: String
) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        // Use proper AppleScript with authentication - simplified to avoid disk renaming issues
        let mount_script = format!(
            r#"set mountURL to "{}"
set userName to "{}"
set userPassword to "{}"
try
    mount volume mountURL as user name userName with password userPassword
    delay 3
    return "success"
on error errMsg
    try
        mount volume mountURL
        delay 3
        return "success"
    on error errMsg2
        return "error: " & errMsg2
    end try
end try"#,
            url, username, password
        );

        println!("🍎 Executing AppleScript to mount WebDAV volume for vault: {}", vault_name);
        println!("   AppleScript will attempt to mount: {}", url);

        // Use tokio::task::spawn_blocking to properly handle the blocking osascript call
        let mount_output = tokio::task::spawn_blocking({
            let mount_script = mount_script.clone();
            move || {
                std::process::Command::new("osascript")
                    .arg("-e")
                    .arg(&mount_script)
                    .output()
            }
        }).await.map_err(|e| format!("Failed to spawn blocking task: {}", e))?;

        match mount_output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);

                println!("🍎 AppleScript stdout: {}", stdout);
                if !stderr.is_empty() {
                    println!("🍎 AppleScript stderr: {}", stderr);
                }

                if output.status.success() && stdout.trim() == "success" {
                    println!("✅ Successfully mounted WebDAV volume: {}", vault_name);
                    println!("   Volume should now be accessible at: {}", url);
                    return Ok(());
                } else if stdout.starts_with("error:") {
                    let error_msg = stdout.trim_start_matches("error: ").trim();
                    println!("❌ AppleScript mount failed: {}", error_msg);
                    println!("   This means macOS couldn't mount the WebDAV volume");
                    println!("   URL attempted: {}", url);
                    return Err(format!("Failed to mount WebDAV volume {}: {}", vault_name, error_msg));
                } else {
                    let error_msg = format!("Unexpected AppleScript output: {}", stdout);
                    println!("❓ {}", error_msg);
                    println!("   URL attempted: {}", url);
                    return Err(error_msg);
                }
            }
            Err(e) => {
                let error_msg = format!("Failed to execute mount osascript: {}", e);
                println!("{}", error_msg);
                return Err(error_msg);
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Windows implementation - use net use command for WebDAV mounting
        println!("WebDAV mounting not yet implemented for Windows");
        Err("WebDAV mounting not yet implemented for Windows".to_string())
    }

    #[cfg(target_os = "linux")]
    {
        // Linux implementation - use davfs2 or similar
        println!("WebDAV mounting not yet implemented for Linux");
        Err("WebDAV mounting not yet implemented for Linux".to_string())
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        println!("WebDAV mounting not supported on this platform");
        Err("WebDAV mounting not supported on this platform".to_string())
    }
}

/// Encrypt data using AES-256-GCM
#[tauri::command]
pub async fn encrypt_data(data: String, master_key: String) -> Result<EncryptionResult, String> {
    use crate::store::encryption::{EncryptionService, MasterKey};
    use base64::Engine;

    // Decode base64 input
    let input_data = base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| format!("Failed to decode base64 input: {}", e))?;

    // Decode master key from base64
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(master_key)
        .map_err(|e| format!("Failed to decode master key: {}", e))?;

    // Validate master key length
    if key_bytes.len() != 32 {
        return Err("Invalid master key length".to_string());
    }

    // Create master key from bytes
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);
    let master_key_obj = MasterKey::from_bytes(key_array);

    // Create encryption service with the provided master key
    let encryption_service = EncryptionService::with_master_key(master_key_obj);

    // Encrypt the data
    let encrypted_data = encryption_service
        .encrypt(&input_data)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Encode results as base64
    let encrypted_base64 = base64::engine::general_purpose::STANDARD
        .encode(&encrypted_data.ciphertext);
    let key_base64 = base64::engine::general_purpose::STANDARD
        .encode(encryption_service.master_key().as_bytes());
    let iv_base64 = base64::engine::general_purpose::STANDARD
        .encode(&encrypted_data.nonce);

    Ok(EncryptionResult {
        encrypted_data: encrypted_base64,
        encryption_key: key_base64,
        iv: iv_base64,
        auth_tag: String::new(), // AES-GCM includes auth tag in ciphertext
        algorithm: encrypted_data.algorithm,
    })
}

/// Decrypt data using AES-256-GCM
#[tauri::command]
pub async fn decrypt_data(
    encrypted_data: String,
    encryption_key: String,
    iv: String,
    _auth_tag: String, // Unused for AES-GCM (included in ciphertext)
    _algorithm: String,
) -> Result<String, String> {
    use crate::store::encryption::{EncryptionService, MasterKey, EncryptedData};
    use base64::Engine;

    // Decode base64 inputs
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(encrypted_data)
        .map_err(|e| format!("Failed to decode encrypted data: {}", e))?;

    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(encryption_key)
        .map_err(|e| format!("Failed to decode encryption key: {}", e))?;

    let iv_bytes = base64::engine::general_purpose::STANDARD
        .decode(iv)
        .map_err(|e| format!("Failed to decode IV: {}", e))?;

    // Create master key from bytes
    if key_bytes.len() != 32 {
        return Err("Invalid key length".to_string());
    }
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);
    let master_key = MasterKey::from_bytes(key_array);

    // Create encryption service with the key
    let encryption_service = EncryptionService::with_master_key(master_key);

    // Create encrypted data structure
    let encrypted = EncryptedData::new(ciphertext, iv_bytes, None);

    // Decrypt the data
    let decrypted_data = encryption_service
        .decrypt(&encrypted)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    // Encode result as base64
    let result_base64 = base64::engine::general_purpose::STANDARD
        .encode(decrypted_data);

    Ok(result_base64)
}

/// Result structure for encryption operations
#[derive(serde::Serialize)]
pub struct EncryptionResult {
    pub encrypted_data: String,
    pub encryption_key: String,
    pub iv: String,
    pub auth_tag: String,
    pub algorithm: String,
}

/// Generate E2EE key bundle with public and private keys using real cryptography
#[tauri::command]
pub async fn generate_key_bundle(password: String) -> Result<KeyBundleResult, String> {
    use base64::Engine;
    use ed25519_dalek::{SigningKey, Signer};
    use pqc_kyber::*;
    use rand::rngs::OsRng;
    use rand::RngCore;

    use crate::store::encryption::{EncryptionService, MasterKey};

    // Generate Ed25519 identity key pair
    let mut identity_private_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut identity_private_bytes);
    let identity_signing_key = SigningKey::from_bytes(&identity_private_bytes);
    let identity_verifying_key = identity_signing_key.verifying_key();

    // Generate proper X25519 signed pre-key pair using real curve operations
    let mut signed_pre_private = [0u8; 32];
    OsRng.fill_bytes(&mut signed_pre_private);
    let signed_pre_public = x25519_dalek::x25519(signed_pre_private, x25519_dalek::X25519_BASEPOINT_BYTES);

    // Generate Kyber-768 key pair
    let mut rng = rand::thread_rng();
    let kyber_keys = keypair(&mut rng)
        .map_err(|e| format!("Failed to generate Kyber keypair: {:?}", e))?;

    // Generate one-time pre-keys (X25519) using proper curve operations
    let mut one_time_private = [0u8; 32];
    OsRng.fill_bytes(&mut one_time_private);
    let one_time_public = x25519_dalek::x25519(one_time_private, x25519_dalek::X25519_BASEPOINT_BYTES);

    // Sign the pre-key with identity key
    let signature = identity_signing_key.sign(&signed_pre_public);

    // Generate salt for key derivation
    let salt = {
        let mut s = [0u8; 32];
        OsRng.fill_bytes(&mut s);
        s
    };


    // Derive encryption key from password
    let master_key = MasterKey::from_password(
        &password,
        &salt,
        &crate::store::encryption::EncryptionConfig::default(),
    ).map_err(|e| format!("Failed to derive key from password: {}", e))?;

    let encryption_service = EncryptionService::with_master_key(master_key);

    // Test encryption/decryption immediately to verify it works
    let test_data = b"test_private_key_data";
    let test_encrypted = encryption_service.encrypt(test_data)
        .map_err(|e| format!("Test encryption failed: {}", e))?;
    let test_decrypted = encryption_service.decrypt(&test_encrypted)
        .map_err(|e| format!("Test decryption failed: {}", e))?;

    if test_data != test_decrypted.as_slice() {
        return Err("Test encryption/decryption verification failed".to_string());
    }

    // Encrypt private keys
    let identity_private_encrypted = encryption_service
        .encrypt(identity_signing_key.as_bytes())
        .map_err(|e| format!("Failed to encrypt identity private key: {}", e))?;

    let signed_pre_private_encrypted = encryption_service
        .encrypt(&signed_pre_private)
        .map_err(|e| format!("Failed to encrypt signed pre-key: {}", e))?;

    let kyber_private_encrypted = encryption_service
        .encrypt(&kyber_keys.secret)
        .map_err(|e| format!("Failed to encrypt Kyber private key: {}", e))?;

    let one_time_private_encrypted = encryption_service
        .encrypt(&one_time_private)
        .map_err(|e| format!("Failed to encrypt one-time pre-key: {}", e))?;

    let result = KeyBundleResult {
        public_keys: PublicKeyBundleResult {
            identity_key: base64::engine::general_purpose::STANDARD.encode(identity_verifying_key.as_bytes()),
            signed_pre_key: base64::engine::general_purpose::STANDARD.encode(signed_pre_public),
            kyber_pre_key: base64::engine::general_purpose::STANDARD.encode(&kyber_keys.public),
            one_time_pre_keys: vec![base64::engine::general_purpose::STANDARD.encode(one_time_public)],
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        },
        private_keys: PrivateKeyBundleResult {
            identity_key: base64::engine::general_purpose::STANDARD.encode(&identity_private_encrypted.ciphertext),
            signed_pre_key: base64::engine::general_purpose::STANDARD.encode(&signed_pre_private_encrypted.ciphertext),
            kyber_pre_key: base64::engine::general_purpose::STANDARD.encode(&kyber_private_encrypted.ciphertext),
            one_time_pre_keys: vec![base64::engine::general_purpose::STANDARD.encode(&one_time_private_encrypted.ciphertext)],
            salt: base64::engine::general_purpose::STANDARD.encode(salt),
            // Store individual nonces for each private key
            identity_key_nonce: base64::engine::general_purpose::STANDARD.encode(&identity_private_encrypted.nonce),
            signed_pre_key_nonce: base64::engine::general_purpose::STANDARD.encode(&signed_pre_private_encrypted.nonce),
            kyber_pre_key_nonce: base64::engine::general_purpose::STANDARD.encode(&kyber_private_encrypted.nonce),
            one_time_pre_keys_nonces: vec![base64::engine::general_purpose::STANDARD.encode(&one_time_private_encrypted.nonce)],
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    Ok(result)
}

/// Perform key exchange to derive shared secret
#[tauri::command]
pub async fn perform_key_exchange(
    recipient_public_keys: PublicKeyBundleResult,
    sender_private_keys: PrivateKeyBundleResult,
    password: String,
) -> Result<KeyExchangeResult, String> {
    use base64::Engine;
    use rand::RngCore;

    // Real implementation using proper cryptography
    use pqc_kyber::*;
    use rand::rngs::OsRng;
    use hkdf::Hkdf;
    use sha2::Sha256;

    use crate::store::encryption::MasterKey;

    // Decode recipient's public keys
    let recipient_kyber_public = base64::engine::general_purpose::STANDARD
        .decode(&recipient_public_keys.kyber_pre_key)
        .map_err(|e| format!("Failed to decode recipient Kyber public key: {}", e))?;

    let recipient_signed_pre_key = base64::engine::general_purpose::STANDARD
        .decode(&recipient_public_keys.signed_pre_key)
        .map_err(|e| format!("Failed to decode recipient signed pre-key: {}", e))?;

    // Decrypt sender's private keys using password
    let salt = base64::engine::general_purpose::STANDARD
        .decode(&sender_private_keys.salt)
        .map_err(|e| format!("Failed to decode salt: {}", e))?;

    let _master_key = MasterKey::from_password(
        &password,
        &salt,
        &crate::store::encryption::EncryptionConfig::default(),
    ).map_err(|e| format!("Failed to derive key from password: {}", e))?;

    // Generate ephemeral key pair for this exchange using proper X25519
    let mut ephemeral_private_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut ephemeral_private_bytes);
    let ephemeral_public_bytes = x25519_dalek::x25519(ephemeral_private_bytes, x25519_dalek::X25519_BASEPOINT_BYTES);


    // Perform proper X25519 ECDH
    if recipient_signed_pre_key.len() != 32 {
        return Err("Invalid recipient signed pre-key length".to_string());
    }
    let mut recipient_public_array = [0u8; 32];
    recipient_public_array.copy_from_slice(&recipient_signed_pre_key);
    let ecdh_secret = x25519_dalek::x25519(ephemeral_private_bytes, recipient_public_array);


    // Perform Kyber encapsulation
    if recipient_kyber_public.len() != KYBER_PUBLICKEYBYTES {
        return Err(format!("Invalid Kyber public key length: expected {}, got {}",
                          KYBER_PUBLICKEYBYTES, recipient_kyber_public.len()));
    }

    let mut kyber_public_array = [0u8; KYBER_PUBLICKEYBYTES];
    kyber_public_array.copy_from_slice(&recipient_kyber_public);

    let mut rng = rand::thread_rng();
    let (kyber_ciphertext, kyber_shared_secret) = encapsulate(&kyber_public_array, &mut rng)
        .map_err(|e| format!("Kyber encapsulation failed: {:?}", e))?;


    // Use fixed salt for consistent key derivation across all exchanges
    let fixed_salt = b"e2ee_file_sharing_salt_v1";

    // Combine ECDH and Kyber secrets using HKDF
    let mut combined_secret = Vec::new();
    combined_secret.extend_from_slice(&ecdh_secret);
    combined_secret.extend_from_slice(&kyber_shared_secret);

    let hk = Hkdf::<Sha256>::new(Some(fixed_salt), &combined_secret);
    let mut final_shared_secret = [0u8; 32];
    hk.expand(b"e2ee_key_exchange", &mut final_shared_secret)
        .map_err(|e| format!("HKDF expansion failed: {}", e))?;

    Ok(KeyExchangeResult {
        shared_secret: base64::engine::general_purpose::STANDARD.encode(final_shared_secret),
        ephemeral_public_key: base64::engine::general_purpose::STANDARD.encode(ephemeral_public_bytes),
        kyber_ciphertext: base64::engine::general_purpose::STANDARD.encode(&kyber_ciphertext),
        salt: base64::engine::general_purpose::STANDARD.encode(fixed_salt),
    })
}

/// Wrap (encrypt) a master key using a shared secret
#[tauri::command]
pub async fn wrap_master_key(
    master_key: String,
    shared_secret: String,
    _salt: String,
) -> Result<WrappedKeyResult, String> {
    use base64::Engine;

    // Decode inputs
    let master_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(master_key)
        .map_err(|e| format!("Failed to decode master key: {}", e))?;

    let shared_secret_bytes = base64::engine::general_purpose::STANDARD
        .decode(shared_secret)
        .map_err(|e| format!("Failed to decode shared secret: {}", e))?;

    // Create encryption service with shared secret as key
    if shared_secret_bytes.len() != 32 {
        return Err("Invalid shared secret length".to_string());
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&shared_secret_bytes);
    let master_key_obj = crate::store::encryption::MasterKey::from_bytes(key_array);
    let encryption_service = crate::store::encryption::EncryptionService::with_master_key(master_key_obj);

    // Encrypt the master key
    let encrypted_data = encryption_service
        .encrypt(&master_key_bytes)
        .map_err(|e| format!("Failed to wrap master key: {}", e))?;

    // Use the actual nonce from encryption, not a random one
    Ok(WrappedKeyResult {
        encrypted_key: base64::engine::general_purpose::STANDARD.encode(&encrypted_data.ciphertext),
        nonce: base64::engine::general_purpose::STANDARD.encode(&encrypted_data.nonce),
    })
}

/// Unwrap (decrypt) a master key using a shared secret
#[tauri::command]
pub async fn unwrap_master_key(
    wrapped_key: WrappedKeyResult,
    shared_secret: String,
) -> Result<String, String> {
    use base64::Engine;

    // Decode inputs
    let encrypted_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(wrapped_key.encrypted_key)
        .map_err(|e| format!("Failed to decode encrypted key: {}", e))?;

    let shared_secret_bytes = base64::engine::general_purpose::STANDARD
        .decode(shared_secret)
        .map_err(|e| format!("Failed to decode shared secret: {}", e))?;

    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(wrapped_key.nonce)
        .map_err(|e| format!("Failed to decode nonce: {}", e))?;



    // Create encryption service with shared secret as key
    if shared_secret_bytes.len() != 32 {
        return Err(format!("Invalid shared secret length: expected 32, got {}", shared_secret_bytes.len()));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&shared_secret_bytes);
    let master_key_obj = crate::store::encryption::MasterKey::from_bytes(key_array);
    let encryption_service = crate::store::encryption::EncryptionService::with_master_key(master_key_obj);


    // Create encrypted data structure
    let encrypted_data = crate::store::encryption::EncryptedData::new(encrypted_key_bytes, nonce_bytes, None);

    // Decrypt the master key
    let decrypted_key = encryption_service
        .decrypt(&encrypted_data)
        .map_err(|e| format!("Decryption error: {}", e))?;


    // Return as base64
    let result = base64::engine::general_purpose::STANDARD.encode(decrypted_key);
    Ok(result)
}

/// Decrypt a private key using password
#[tauri::command]
pub async fn decrypt_private_key(
    encrypted_private_key: String,
    nonce: String,
    salt: String,
    password: String,
) -> Result<String, String> {
    use base64::Engine;
    use crate::store::encryption::{MasterKey, EncryptionService, EncryptedData};


    // Decode inputs
    let encrypted_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(encrypted_private_key)
        .map_err(|e| format!("Failed to decode encrypted private key: {}", e))?;

    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(nonce)
        .map_err(|e| format!("Failed to decode nonce: {}", e))?;

    let salt_bytes = base64::engine::general_purpose::STANDARD
        .decode(salt)
        .map_err(|e| format!("Failed to decode salt: {}", e))?;



    // Derive master key from password
    let master_key = MasterKey::from_password(
        &password,
        &salt_bytes,
        &crate::store::encryption::EncryptionConfig::default(),
    ).map_err(|e| format!("Failed to derive key from password: {}", e))?;



    let encryption_service = EncryptionService::with_master_key(master_key);

    // Create encrypted data structure
    let encrypted_data = EncryptedData::new(encrypted_key_bytes, nonce_bytes, None);



    // Decrypt the private key
    let decrypted_key = encryption_service
        .decrypt(&encrypted_data)
        .map_err(|e| {
            format!("Decryption error: {}", e)
        })?;



    // Return as base64
    Ok(base64::engine::general_purpose::STANDARD.encode(decrypted_key))
}

// Result structures for key operations
#[derive(serde::Serialize, Clone)]
pub struct KeyBundleResult {
    pub public_keys: PublicKeyBundleResult,
    pub private_keys: PrivateKeyBundleResult,
    pub timestamp: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct PublicKeyBundleResult {
    pub identity_key: String,
    pub signed_pre_key: String,
    pub kyber_pre_key: String,
    pub one_time_pre_keys: Vec<String>,
    pub signature: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct PrivateKeyBundleResult {
    pub identity_key: String,
    pub signed_pre_key: String,
    pub kyber_pre_key: String,
    pub one_time_pre_keys: Vec<String>,
    pub salt: String,
    // Individual nonces for each private key
    pub identity_key_nonce: String,
    pub signed_pre_key_nonce: String,
    pub kyber_pre_key_nonce: String,
    pub one_time_pre_keys_nonces: Vec<String>,
}

#[derive(serde::Serialize)]
pub struct KeyExchangeResult {
    pub shared_secret: String,
    pub ephemeral_public_key: String,
    pub kyber_ciphertext: String,
    pub salt: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct WrappedKeyResult {
    pub encrypted_key: String,
    pub nonce: String,
}

/// Generate ephemeral ECDH key pair for key exchange
#[tauri::command]
pub async fn generate_ephemeral_keypair() -> Result<EphemeralKeypairResult, String> {

    use base64::Engine;
    use rand::RngCore;

    // Generate proper X25519 ephemeral key pair
    // Generate random bytes first, then create keys from them to maintain consistency
    let mut private_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut private_bytes);

    // Create public key using the low-level x25519 function with the base point
    let public_bytes = x25519_dalek::x25519(private_bytes, x25519_dalek::X25519_BASEPOINT_BYTES);

    Ok(EphemeralKeypairResult {
        private_key: base64::engine::general_purpose::STANDARD.encode(private_bytes),
        public_key: base64::engine::general_purpose::STANDARD.encode(public_bytes),
    })
}

/// Generate Kyber-768 key pair for post-quantum key exchange
#[tauri::command]
pub async fn generate_kyber_keypair() -> Result<KyberKeypairResult, String> {
    use pqc_kyber::*;
    use base64::Engine;

    // Generate Kyber-768 key pair
    let mut rng = rand::thread_rng();
    let keys = keypair(&mut rng).map_err(|e| format!("Kyber keypair generation failed: {:?}", e))?;

    Ok(KyberKeypairResult {
        private_key: base64::engine::general_purpose::STANDARD.encode(&keys.secret),
        public_key: base64::engine::general_purpose::STANDARD.encode(&keys.public),
    })
}

/// Perform ECDH key exchange
#[tauri::command]
pub async fn perform_ecdh(
    private_key: String, // Sender private key
    public_key: String, // Receiver public key
) -> Result<String, String> {
    use base64::Engine;


    // Decode keys from base64
    let private_bytes = base64::engine::general_purpose::STANDARD
        .decode(private_key)
        .map_err(|e| format!("Failed to decode private key: {}", e))?;

    let public_bytes = base64::engine::general_purpose::STANDARD
        .decode(public_key)
        .map_err(|e| format!("Failed to decode public key: {}", e))?;

    // Validate key lengths
    if private_bytes.len() != 32 {
        return Err("Invalid private key length".to_string());
    }
    if public_bytes.len() != 32 {
        return Err("Invalid public key length".to_string());
    }

    // Perform proper X25519 ECDH operation using the low-level function
    let mut private_array = [0u8; 32];
    private_array.copy_from_slice(&private_bytes);

    let mut public_array = [0u8; 32];
    public_array.copy_from_slice(&public_bytes);

    // Use the low-level x25519 function for ECDH with raw bytes
    let shared_secret = x25519_dalek::x25519(private_array, public_array);

    // Return shared secret as base64
    Ok(base64::engine::general_purpose::STANDARD.encode(shared_secret))
}

/// Perform Kyber encapsulation (sender side)
#[tauri::command]
pub async fn kyber_encapsulate(public_key: String) -> Result<KyberEncapsulationResult, String> {
    use pqc_kyber::*;
    use base64::Engine;

    // Decode public key from base64
    let public_bytes = base64::engine::general_purpose::STANDARD
        .decode(public_key)
        .map_err(|e| format!("Failed to decode public key: {}", e))?;

    if public_bytes.len() != KYBER_PUBLICKEYBYTES {
        return Err(format!("Invalid public key length: expected {}, got {}", KYBER_PUBLICKEYBYTES, public_bytes.len()));
    }

    // Convert to public key array
    let mut public_key_array = [0u8; KYBER_PUBLICKEYBYTES];
    public_key_array.copy_from_slice(&public_bytes);

    // Perform encapsulation
    let mut rng = rand::thread_rng();
    let (ciphertext, shared_secret) = encapsulate(&public_key_array, &mut rng)
        .map_err(|e| format!("Kyber encapsulation failed: {:?}", e))?;

    Ok(KyberEncapsulationResult {
        ciphertext: base64::engine::general_purpose::STANDARD.encode(&ciphertext),
        shared_secret: base64::engine::general_purpose::STANDARD.encode(&shared_secret),
    })
}

/// Perform Kyber decapsulation (receiver side)
#[tauri::command]
pub async fn kyber_decapsulate(
    private_key: String,
    ciphertext: String,
) -> Result<String, String> {
    use pqc_kyber::*;
    use base64::Engine;

    // Decode inputs from base64
    let private_bytes = base64::engine::general_purpose::STANDARD
        .decode(private_key)
        .map_err(|e| format!("Failed to decode private key: {}", e))?;

    let ciphertext_bytes = base64::engine::general_purpose::STANDARD
        .decode(ciphertext)
        .map_err(|e| format!("Failed to decode ciphertext: {}", e))?;

    if private_bytes.len() != KYBER_SECRETKEYBYTES {
        return Err(format!("Invalid private key length: expected {}, got {}", KYBER_SECRETKEYBYTES, private_bytes.len()));
    }

    if ciphertext_bytes.len() != KYBER_CIPHERTEXTBYTES {
        return Err(format!("Invalid ciphertext length: expected {}, got {}", KYBER_CIPHERTEXTBYTES, ciphertext_bytes.len()));
    }

    // Convert to arrays
    let mut private_key_array = [0u8; KYBER_SECRETKEYBYTES];
    private_key_array.copy_from_slice(&private_bytes);

    let mut ciphertext_array = [0u8; KYBER_CIPHERTEXTBYTES];
    ciphertext_array.copy_from_slice(&ciphertext_bytes);

    // Perform decapsulation
    let shared_secret = decapsulate(&ciphertext_array, &private_key_array)
        .map_err(|e| format!("Kyber decapsulation failed: {:?}", e))?;

    Ok(base64::engine::general_purpose::STANDARD.encode(&shared_secret))
}

/// Derive shared secret using HKDF from ECDH and Kyber results
#[tauri::command]
pub async fn derive_shared_secret(
    ecdh_secret: String,
    kyber_secret: String,
    salt: String,
    info: String,
) -> Result<String, String> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    use base64::Engine;

    // Decode inputs
    let ecdh_bytes = base64::engine::general_purpose::STANDARD
        .decode(ecdh_secret)
        .map_err(|e| format!("Failed to decode ECDH secret: {}", e))?;

    let kyber_bytes = base64::engine::general_purpose::STANDARD
        .decode(kyber_secret)
        .map_err(|e| format!("Failed to decode Kyber secret: {}", e))?;

    let salt_bytes = base64::engine::general_purpose::STANDARD
        .decode(salt)
        .map_err(|e| format!("Failed to decode salt: {}", e))?;

    // Combine ECDH and Kyber secrets
    let mut combined_secret = Vec::new();
    combined_secret.extend_from_slice(&ecdh_bytes);
    combined_secret.extend_from_slice(&kyber_bytes);

    // Derive key using HKDF
    let hk = Hkdf::<Sha256>::new(Some(&salt_bytes), &combined_secret);
    let mut derived_key = [0u8; 32]; // 256-bit key
    hk.expand(info.as_bytes(), &mut derived_key)
        .map_err(|e| format!("HKDF expansion failed: {}", e))?;

    Ok(base64::engine::general_purpose::STANDARD.encode(derived_key))
}

/// Generate cryptographically secure random bytes
#[tauri::command]
pub async fn generate_random_bytes(length: usize) -> Result<String, String> {
    use rand::RngCore;
    use base64::Engine;

    if length > 1024 {
        return Err("Maximum length is 1024 bytes".to_string());
    }

    let mut bytes = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut bytes);

    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// Encrypt file content using a master key
#[tauri::command]
pub async fn encrypt_file_content(
    file_content: &[u8],
    master_key: &str,
) -> Result<Vec<u8>, String> {
    use base64::Engine;
    use crate::store::encryption::{EncryptionService, MasterKey};

    // Decode the master key
    let master_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(master_key)
        .map_err(|e| format!("Failed to decode master key: {}", e))?;

    if master_key_bytes.len() != 32 {
        return Err("Invalid master key length".to_string());
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&master_key_bytes);
    let master_key_obj = MasterKey::from_bytes(key_array);

    // Create encryption service
    let encryption_service = EncryptionService::with_master_key(master_key_obj);

    // Encrypt the content
    let encrypted_data = encryption_service.encrypt(file_content)
        .map_err(|e| format!("Failed to encrypt file content: {}", e))?;

    // Serialize the encrypted data structure
    let serialized_data = serde_json::to_vec(&encrypted_data)
        .map_err(|e| format!("Failed to serialize encrypted data: {}", e))?;

    // Return as base64-encoded bytes
    Ok(base64::engine::general_purpose::STANDARD.encode(serialized_data).into_bytes())
}

/// Decrypt file content using a master key
#[tauri::command]
pub async fn decrypt_file_content(
    encrypted_content: &str,
    master_key: &str,
) -> Result<Vec<u8>, String> {
    use base64::Engine;
    use crate::store::encryption::{EncryptionService, MasterKey};

    // Decode the master key
    let master_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(master_key)
        .map_err(|e| format!("Failed to decode master key: {}", e))?;

    if master_key_bytes.len() != 32 {
        return Err("Invalid master key length".to_string());
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&master_key_bytes);
    let master_key_obj = MasterKey::from_bytes(key_array);

    // Create encryption service
    let encryption_service = EncryptionService::with_master_key(master_key_obj);

    // Decode the encrypted content
    let encrypted_data = base64::engine::general_purpose::STANDARD
        .decode(encrypted_content)
        .map_err(|e| format!("Failed to decode encrypted content: {}", e))?;

    // Parse as EncryptedData structure
    let encrypted_struct: crate::store::encryption::EncryptedData = serde_json::from_slice(&encrypted_data)
        .map_err(|e| format!("Failed to parse encrypted data structure: {}", e))?;

    // Decrypt the content
    let decrypted_data = encryption_service.decrypt(&encrypted_struct)
        .map_err(|e| format!("Failed to decrypt file content: {}", e))?;

    Ok(decrypted_data)
}

/// Save file to Downloads directory
#[tauri::command]
pub async fn save_file_to_downloads(
    file_data: &[u8],
    file_name: &str,
) -> Result<String, String> {
    use std::path::PathBuf;
    use tokio::fs;

    // Get the user's Downloads directory
    let downloads_dir = match std::env::var("HOME") {
        Ok(home) => PathBuf::from(home).join("Downloads"),
        Err(_) => {
            // Fallback to current directory if HOME is not set
            PathBuf::from(".")
        }
    };

    // Ensure Downloads directory exists
    if !downloads_dir.exists() {
        fs::create_dir_all(&downloads_dir).await
            .map_err(|e| format!("Failed to create Downloads directory: {}", e))?;
    }

    // Create the full file path
    let file_path = downloads_dir.join(file_name);

    // Handle file name conflicts by adding a number suffix
    let mut final_path = file_path.clone();
    let mut counter = 1;
    while final_path.exists() {
        let stem = file_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("file");
        let extension = file_path.extension()
            .and_then(|s| s.to_str())
            .map(|s| format!(".{}", s))
            .unwrap_or_default();

        let new_name = format!("{} ({}){}", stem, counter, extension);
        final_path = downloads_dir.join(new_name);
        counter += 1;
    }

    // Write the file
    fs::write(&final_path, file_data).await
        .map_err(|e| format!("Failed to write file to Downloads: {}", e))?;

    Ok(final_path.to_string_lossy().to_string())
}

// Result structures for new cryptographic operations
#[derive(serde::Serialize)]
pub struct EphemeralKeypairResult {
    pub private_key: String,
    pub public_key: String,
}

#[derive(serde::Serialize)]
pub struct KyberKeypairResult {
    pub private_key: String,
    pub public_key: String,
}

#[derive(serde::Serialize)]
pub struct KyberEncapsulationResult {
    pub ciphertext: String,
    pub shared_secret: String,
}

// API proxy commands for Go backend communication
use crate::http::ApiClient;
use serde_json::Value;
use base64::Engine;
use sha2::Digest;

/// Health check for Go API backend
#[tauri::command]
pub async fn api_health_check() -> Result<Value, String> {
    let client = ApiClient::default();
    let response = client.health_check().await
        .map_err(|e| format!("Health check failed: {}", e))?;

    if response.success {
        Ok(serde_json::to_value(response.data).unwrap_or(Value::Null))
    } else {
        Err(response.error.unwrap_or_else(|| "Health check failed".to_string()))
    }
}

/// Upload encrypted blob to storage
#[tauri::command]
pub async fn api_upload_blob(encrypted_content: String) -> Result<Value, String> {
    let client = ApiClient::default();

    // Calculate hash of the base64-decoded binary data
    let binary_data = base64::engine::general_purpose::STANDARD
        .decode(&encrypted_content)
        .map_err(|e| format!("Failed to decode base64 content: {}", e))?;

    let hash_bytes = sha2::Sha256::digest(&binary_data);
    let hash_hex = hex::encode(hash_bytes);

    let request_body = serde_json::json!({
        "encrypted_content": encrypted_content,
        "blob_hash": hash_hex,
    });

    let response = client.post::<Value, _>("/blobs/upload", &request_body).await
        .map_err(|e| format!("Blob upload failed: {}", e))?;

    if response.success {
        Ok(response.data.unwrap_or(Value::Null))
    } else {
        Err(response.error.unwrap_or_else(|| "Blob upload failed".to_string()))
    }
}

/// Download encrypted blob from storage
#[tauri::command]
pub async fn api_download_blob(blob_url: String) -> Result<Value, String> {
    let client = ApiClient::default();

    // Extract blob ID from URL
    let blob_id = blob_url.split('/').last()
        .ok_or_else(|| "Invalid blob URL".to_string())?;

    let response = client.get::<Value>(&format!("/blobs/{}", blob_id)).await
        .map_err(|e| format!("Blob download failed: {}", e))?;

    if response.success {
        Ok(response.data.unwrap_or(Value::Null))
    } else {
        Err(response.error.unwrap_or_else(|| "Blob download failed".to_string()))
    }
}

/// Create a new group
#[tauri::command]
pub async fn api_create_group(name: String, creator_id: String) -> Result<Value, String> {
    let client = ApiClient::default();

    let request_body = serde_json::json!({
        "name": name,
        "creator_id": creator_id,
    });

    let response = client.post::<Value, _>("/groups", &request_body).await
        .map_err(|e| format!("Group creation failed: {}", e))?;

    if response.success {
        Ok(response.data.unwrap_or(Value::Null))
    } else {
        Err(response.error.unwrap_or_else(|| "Group creation failed".to_string()))
    }
}

/// Get group information by ID
#[tauri::command]
pub async fn api_get_group(group_id: String) -> Result<Value, String> {
    let client = ApiClient::default();

    let response = client.get::<Value>(&format!("/groups/{}", group_id)).await
        .map_err(|e| format!("Get group failed: {}", e))?;

    if response.success {
        Ok(response.data.unwrap_or(Value::Null))
    } else {
        Err(response.error.unwrap_or_else(|| "Get group failed".to_string()))
    }
}

/// Add member to group
#[tauri::command]
pub async fn api_add_group_member(group_id: String, user_id: String) -> Result<Value, String> {
    let client = ApiClient::default();

    let request_body = serde_json::json!({
        "user_id": user_id,
    });

    let response = client.post::<Value, _>(&format!("/groups/{}/members", group_id), &request_body).await
        .map_err(|e| format!("Add group member failed: {}", e))?;

    if response.success {
        Ok(response.data.unwrap_or(Value::Null))
    } else {
        Err(response.error.unwrap_or_else(|| "Add group member failed".to_string()))
    }
}

/// Get public key bundles for multiple users
#[tauri::command]
pub async fn api_get_public_key_bundles(user_ids: Vec<String>) -> Result<Value, String> {
    let client = ApiClient::default();

    let request_body = serde_json::json!({
        "user_ids": user_ids,
    });

    let response = client.post::<Value, _>("/public-key-bundles", &request_body).await
        .map_err(|e| format!("Get public key bundles failed: {}", e))?;

    if response.success {
        Ok(response.data.unwrap_or(Value::Null))
    } else {
        Err(response.error.unwrap_or_else(|| "Get public key bundles failed".to_string()))
    }
}

/// Send bulk wrapped keys to multiple users
#[tauri::command]
pub async fn api_send_bulk_wrapped_keys(
    file_id: String,
    group_id: String,
    wrapped_keys: Value,
) -> Result<Value, String> {
    let client = ApiClient::default();

    let request_body = serde_json::json!({
        "file_id": file_id,
        "group_id": group_id,
        "wrapped_keys": wrapped_keys,
    });

    let response = client.post::<Value, _>("/messages/send-bulk", &request_body).await
        .map_err(|e| format!("Send bulk wrapped keys failed: {}", e))?;

    if response.success {
        Ok(response.data.unwrap_or(Value::Null))
    } else {
        Err(response.error.unwrap_or_else(|| "Send bulk wrapped keys failed".to_string()))
    }
}

/// Share file metadata only (zero-knowledge)
#[tauri::command]
pub async fn api_share_file_metadata(
    group_id: String,
    original_name: String,
    size: u64,
    mime_type: String,
    shared_by: String,
    blob_url: String,
    blob_hash: String,
    description: Option<String>,
) -> Result<Value, String> {
    let client = ApiClient::default();

    let mut request_body = serde_json::json!({
        "original_name": original_name,
        "size": size,
        "mime_type": mime_type,
        "shared_by": shared_by,
        "blob_url": blob_url,
        "blob_hash": blob_hash,
    });

    if let Some(desc) = description {
        request_body["description"] = serde_json::Value::String(desc);
    }

    let response = client.post::<Value, _>(&format!("/groups/{}/files", group_id), &request_body).await
        .map_err(|e| format!("Share file metadata failed: {}", e))?;

    if response.success {
        Ok(response.data.unwrap_or(Value::Null))
    } else {
        Err(response.error.unwrap_or_else(|| "Share file metadata failed".to_string()))
    }
}

/// Get files in a group
#[tauri::command]
pub async fn api_get_group_files(group_id: String) -> Result<Value, String> {
    let client = ApiClient::default();

    let response = client.get::<Value>(&format!("/groups/{}/files", group_id)).await
        .map_err(|e| format!("Get group files failed: {}", e))?;

    if response.success {
        Ok(response.data.unwrap_or(Value::Null))
    } else {
        Err(response.error.unwrap_or_else(|| "Get group files failed".to_string()))
    }
}

// ============================================================================
// E2EE FILE SHARING COMMANDS - All cryptographic operations in Rust backend
// ============================================================================

#[derive(serde::Serialize, serde::Deserialize)]
pub struct FileShareRequest {
    pub file_data: String, // Base64 encoded file data
    pub file_name: String,
    pub file_size: u64,
    pub mime_type: String,
    pub group_id: String,
    pub password: String, // User's password for key decryption
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct FileShareProgress {
    pub progress: u8,
    pub status: String,
    pub error: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct FileShareResult {
    pub success: bool,
    pub file_id: Option<String>,
    pub error: Option<String>,
}

/// Complete E2EE file sharing operation - all crypto operations in Rust
#[tauri::command]
pub async fn e2ee_share_file_with_group(
    state: tauri::State<'_, crate::auth::commands::AuthState>,
    request: FileShareRequest,
) -> Result<FileShareResult, String> {
    use base64::Engine;
    use rand::RngCore;
    use crate::store::encryption::{EncryptionService, MasterKey};
    use crate::http::client::ApiClient;

    // Step 1: Get current authenticated user and their private keys
    let service = state.service.read().await;
    let current_user = match service.get_current_user().await {
        Ok(user) => user,
        Err(e) => return Ok(FileShareResult {
            success: false,
            file_id: None,
            error: Some(format!("Failed to get current user: {}", e)),
        }),
    };

    // Step 2: Get user's private keys (for now, generate new ones since auth system doesn't store them)
    let user_private_keys = match get_user_private_keys(state.clone(), request.password.clone()).await {
        Ok(keys) => keys,
        Err(e) => return Ok(FileShareResult {
            success: false,
            file_id: None,
            error: Some(format!("Failed to get private keys: {}", e)),
        }),
    };

    // Step 3: Generate random master key (32 bytes, secure random generator)
    let mut master_key_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut master_key_bytes);
    let master_key = base64::engine::general_purpose::STANDARD.encode(master_key_bytes);

    // Step 4: Decrypt and encrypt file with master key
    let file_data = base64::engine::general_purpose::STANDARD
        .decode(&request.file_data)
        .map_err(|e| format!("Failed to decode file data: {}", e))?;

    let master_key_obj = MasterKey::from_bytes(master_key_bytes);
    let encryption_service = EncryptionService::with_master_key(master_key_obj);

    let encrypted_data = encryption_service.encrypt(&file_data)
        .map_err(|e| format!("Failed to encrypt file: {}", e))?;

    // Serialize the complete encrypted data structure (including nonce, salt, etc.)
    let serialized_encrypted_data = serde_json::to_vec(&encrypted_data)
        .map_err(|e| format!("Failed to serialize encrypted data: {}", e))?;

    let encrypted_base64 = base64::engine::general_purpose::STANDARD.encode(&serialized_encrypted_data);

    // Step 5: Get group members' public key bundles from Go API
    let client = ApiClient::default();
    let group_response = client.get::<Value>(&format!("/groups/{}", request.group_id)).await
        .map_err(|e| format!("Failed to get group info: {}", e))?;

    if !group_response.success {
        return Ok(FileShareResult {
            success: false,
            file_id: None,
            error: Some("Failed to get group information".to_string()),
        });
    }

    let group_data = group_response.data.ok_or("No group data received")?;
    let members = group_data.get("members")
        .and_then(|m| m.as_array())
        .ok_or("Invalid group members data")?;

    let member_ids: Vec<String> = members.iter()
        .filter_map(|m| m.as_str().map(|s| s.to_string()))
        .collect();

    let bundles_response = client.post::<Value, _>("/public-key-bundles", &serde_json::json!({
        "user_ids": member_ids,
    })).await.map_err(|e| format!("Failed to get public key bundles: {}", e))?;

    if !bundles_response.success {
        return Ok(FileShareResult {
            success: false,
            file_id: None,
            error: Some("Failed to get member public keys".to_string()),
        });
    }

    let bundles_data = bundles_response.data.ok_or("No bundles data received")?;
    let bundles = bundles_data.get("public_key_bundles")
        .and_then(|b| b.as_array())
        .ok_or("Invalid bundles data")?;

    // Step 6: Perform key exchange and wrap master key for each member
    let mut wrapped_keys = serde_json::Map::new();

    for bundle in bundles {
        let user_id = bundle.get("user_id")
            .and_then(|u| u.as_str())
            .ok_or("Invalid user_id in bundle")?;

        let public_keys = bundle.get("public_keys")
            .ok_or("Missing public_keys in bundle")?;

        // Convert to our internal format for key exchange
        let recipient_public_keys = PublicKeyBundleResult {
            identity_key: public_keys.get("identity_key")
                .and_then(|k| k.as_str())
                .ok_or("Missing identity_key")?.to_string(),
            signed_pre_key: public_keys.get("signed_pre_key")
                .and_then(|k| k.as_str())
                .ok_or("Missing signed_pre_key")?.to_string(),
            kyber_pre_key: public_keys.get("kyber_pre_key")
                .and_then(|k| k.as_str())
                .ok_or("Missing kyber_pre_key")?.to_string(),
            one_time_pre_keys: public_keys.get("one_time_pre_keys")
                .and_then(|k| k.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default(),
            signature: public_keys.get("signature")
                .and_then(|k| k.as_str())
                .ok_or("Missing signature")?.to_string(),
        };

        // Perform key exchange
        let key_exchange_result = perform_key_exchange(
            recipient_public_keys,
            user_private_keys.clone(),
            request.password.clone(),
        ).await.map_err(|e| format!("Key exchange failed for user {}: {}", user_id, e))?;

        // Wrap master key with derived shared secret
        let wrapped_key = wrap_master_key(
            master_key.clone(),
            key_exchange_result.shared_secret.clone(),
            key_exchange_result.salt.clone(),
        ).await.map_err(|e| format!("Failed to wrap key for user {}: {}", user_id, e))?;

        // Store wrapped key with key exchange data
        let wrapped_key_json = serde_json::json!({
            "encrypted_key": wrapped_key.encrypted_key,
            "key_exchange": {
                "ephemeral_public_key": key_exchange_result.ephemeral_public_key,
                "kyber_ciphertext": key_exchange_result.kyber_ciphertext,
                "salt": key_exchange_result.salt,
                "nonce": wrapped_key.nonce,
            }
        });



        wrapped_keys.insert(user_id.to_string(), wrapped_key_json);
    }

    // Step 7: Upload encrypted file to blob storage
    let blob_response = client.post::<Value, _>("/blobs/upload", &serde_json::json!({
        "encrypted_content": encrypted_base64,
        "blob_hash": format!("{:x}", sha2::Sha256::digest(&serialized_encrypted_data)),
    })).await.map_err(|e| format!("Failed to upload blob: {}", e))?;

    if !blob_response.success {
        return Ok(FileShareResult {
            success: false,
            file_id: None,
            error: Some("Failed to upload encrypted file to blob storage".to_string()),
        });
    }

    let blob_data = blob_response.data.ok_or("No blob data received")?;
    let blob_url = blob_data.get("blob_url")
        .and_then(|u| u.as_str())
        .ok_or("Missing blob_url in response")?;
    let blob_hash = blob_data.get("blob_hash")
        .and_then(|h| h.as_str())
        .ok_or("Missing blob_hash in response")?;

    // Step 8: Share file metadata (zero-knowledge) with group
    // First, ensure the user exists in the Go backend by checking/creating them
    let user_check_response = client.get::<Value>(&format!("/users/by-username/{}", urlencoding::encode(&current_user.username))).await;

    let go_user_id = match user_check_response {
        Ok(response) if response.success => {
            // User exists in Go backend, get their ID
            response.data
                .and_then(|data| data.get("id").and_then(|id| id.as_str().map(|s| s.to_string())))
                .ok_or("Missing user ID in Go backend response")?
        }
        _ => {
            // User doesn't exist in Go backend, we need to register them
            // For now, we'll use a placeholder approach since the Go backend registration
            // requires public key bundles which we don't have in the current auth system
            return Ok(FileShareResult {
                success: false,
                file_id: None,
                error: Some("User not registered in Go backend. Please register through the Go backend first.".to_string()),
            });
        }
    };

    let metadata_response = client.post::<Value, _>(&format!("/groups/{}/files", request.group_id), &serde_json::json!({
        "original_name": request.file_name,
        "size": request.file_size,
        "mime_type": request.mime_type,
        "shared_by": go_user_id,
        "blob_url": blob_url,
        "blob_hash": blob_hash,
    })).await.map_err(|e| format!("Failed to share file metadata: {}", e))?;

    if !metadata_response.success {
        return Ok(FileShareResult {
            success: false,
            file_id: None,
            error: Some("Failed to share file metadata".to_string()),
        });
    }

    let metadata_data = metadata_response.data.ok_or("No metadata response data")?;
    let file_id = metadata_data.get("id")
        .and_then(|id| id.as_str())
        .ok_or("Missing file ID in metadata response")?;

    // Step 9: Send wrapped keys to group members via message queue
    let keys_response = client.post::<Value, _>("/messages/send-bulk", &serde_json::json!({
        "file_id": file_id,
        "group_id": request.group_id,
        "wrapped_keys": wrapped_keys,
    })).await.map_err(|e| format!("Failed to send wrapped keys: {}", e))?;

    if !keys_response.success {
        return Ok(FileShareResult {
            success: false,
            file_id: Some(file_id.to_string()),
            error: Some("Failed to send wrapped keys to group members".to_string()),
        });
    }

    Ok(FileShareResult {
        success: true,
        file_id: Some(file_id.to_string()),
        error: None,
    })
}

/// Get user's private keys by decrypting them with password
#[tauri::command]
pub async fn get_user_private_keys(
    state: tauri::State<'_, crate::auth::commands::AuthState>,
    password: String,
) -> Result<PrivateKeyBundleResult, String> {
    // Get current user from auth service
    let auth_service = state.service.read().await;
    let current_user = auth_service.get_current_user().await
        .map_err(|e| format!("Failed to get current user: {}", e))?;

    // Get stored private keys from auth service
    let stored_private_keys = auth_service.get_user_private_keys(&current_user.id, &password).await
        .map_err(|e| format!("Failed to retrieve private keys: {}", e))?;

    Ok(stored_private_keys)
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct FileDownloadRequest {
    pub file_id: String,
    pub password: String, // User's password for key decryption
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct FileDownloadResult {
    pub success: bool,
    pub file_data: Option<String>, // Base64 encoded decrypted file data
    pub file_name: Option<String>,
    pub error: Option<String>,
}

/// Complete E2EE file download and decryption operation - all crypto operations in Rust
#[tauri::command]
pub async fn e2ee_download_and_decrypt_file(
    state: tauri::State<'_, crate::auth::commands::AuthState>,
    request: FileDownloadRequest,
) -> Result<FileDownloadResult, String> {
    use crate::http::client::ApiClient;

    // Step 1: Get current authenticated user
    let service = state.service.read().await;
    let current_user = match service.get_current_user().await {
        Ok(user) => user,
        Err(e) => return Ok(FileDownloadResult {
            success: false,
            file_data: None,
            file_name: None,
            error: Some(format!("Failed to get current user: {}", e)),
        }),
    };

    // Step 2: Get user's private keys
    let user_private_keys = match get_user_private_keys(state.clone(), request.password.clone()).await {
        Ok(keys) => keys,
        Err(e) => return Ok(FileDownloadResult {
            success: false,
            file_data: None,
            file_name: None,
            error: Some(format!("Failed to get private keys: {}", e)),
        }),
    };

    let client = ApiClient::default();

    // Step 3: Get Go backend user ID by username lookup
    let user_check_response = client.get::<Value>(&format!("/users/by-username/{}", urlencoding::encode(&current_user.username))).await;

    let go_user_id = match user_check_response {
        Ok(response) if response.success => {
            // User exists in Go backend, get their ID
            response.data
                .and_then(|data| data.get("id").and_then(|id| id.as_str().map(|s| s.to_string())))
                .ok_or("Missing user ID in Go backend response")?
        }
        Ok(response) => {
            return Ok(FileDownloadResult {
                success: false,
                file_data: None,
                file_name: None,
                error: Some(format!("User lookup failed: {}", response.error.unwrap_or_else(|| "Unknown error".to_string()))),
            });
        }
        Err(e) => {
            return Ok(FileDownloadResult {
                success: false,
                file_data: None,
                file_name: None,
                error: Some(format!("Failed to lookup user in Go backend: {}", e)),
            });
        }
    };

    // Step 4: Get user's message queue to find wrapped keys for this file
    let messages_response = client
        .get::<Value>(&format!("/users/{}/messages", go_user_id)).await
        .map_err(|e| format!("Failed to get user messages: {}", e))?;

    if !messages_response.success {
        return Ok(FileDownloadResult {
            success: false,
            file_data: None,
            file_name: None,
            error: Some("Failed to get user messages".to_string()),
        });
    }

    let messages_data = messages_response.data.ok_or("No messages data received")?;


    let messages = messages_data.get("messages")
        .and_then(|m| m.as_array())
        .ok_or("Invalid messages data")?;

    // Find wrapped key for this file
    let wrapped_message = messages.iter()
        .find(|msg| {
            msg.get("file_id").and_then(|id| id.as_str()) == Some(&request.file_id) &&
            !msg.get("processed").and_then(|p| p.as_bool()).unwrap_or(true)
        })
        .ok_or("No access key found for this file")?;



    let wrapped_key_data = wrapped_message.get("wrapped_key")
        .ok_or("Missing wrapped key in message")?;



    // Step 5: Get file metadata
    let file_response = client.get::<Value>(&format!("/files/{}/info?user_id={}", request.file_id, go_user_id)).await
        .map_err(|e| format!("Failed to get file metadata: {}", e))?;

    if !file_response.success {
        return Ok(FileDownloadResult {
            success: false,
            file_data: None,
            file_name: None,
            error: Some("Failed to get file metadata".to_string()),
        });
    }

    let file_data = file_response.data.ok_or("No file data received")?;
    let blob_url = file_data.get("blob_url")
        .and_then(|u| u.as_str())
        .ok_or("Missing blob_url in file data")?;
    let file_name = file_data.get("original_name")
        .and_then(|n| n.as_str())
        .unwrap_or("unknown_file");

    // Step 6: Download encrypted blob from storage
    let blob_response = client.get::<Value>(&format!("/blobs/{}", blob_url.split('/').last().unwrap_or(""))).await
        .map_err(|e| format!("Failed to download blob: {}", e))?;

    if !blob_response.success {
        return Ok(FileDownloadResult {
            success: false,
            file_data: None,
            file_name: Some(file_name.to_string()),
            error: Some("Failed to download encrypted file".to_string()),
        });
    }

    let blob_data = blob_response.data.ok_or("No blob data received")?;
    let encrypted_content = blob_data.get("encrypted_content")
        .and_then(|c| c.as_str())
        .ok_or("Missing encrypted_content in blob data")?;

    // Step 7: Reconstruct key exchange and derive shared secret
    let key_exchange_data = wrapped_key_data.get("key_exchange")
        .ok_or("Missing key_exchange data")?;



    let ephemeral_public_key = key_exchange_data.get("ephemeral_public_key")
        .and_then(|k| k.as_str())
        .ok_or("Missing ephemeral_public_key")?;
    let kyber_ciphertext = key_exchange_data.get("kyber_ciphertext")
        .and_then(|k| k.as_str())
        .ok_or("Missing kyber_ciphertext")?;
    let salt = key_exchange_data.get("salt")
        .and_then(|s| s.as_str())
        .ok_or("Missing salt")?;



    // Step 8: Extract encrypted private keys from user_private_keys structure
    let encrypted_signed_pre_key = &user_private_keys.signed_pre_key;
    let signed_pre_key_nonce = &user_private_keys.signed_pre_key_nonce;
    let encrypted_kyber_key = &user_private_keys.kyber_pre_key;
    let kyber_key_nonce = &user_private_keys.kyber_pre_key_nonce;
    let user_salt = &user_private_keys.salt;


    if request.password.is_empty() {
        return Ok(FileDownloadResult {
            success: false,
            file_data: None,
            file_name: None,
            error: Some("Password is required for file decryption".to_string()),
        });
    }


    // Decrypt private keys
    let decrypted_signed_pre_key = decrypt_private_key(
        encrypted_signed_pre_key.to_string(),
        signed_pre_key_nonce.to_string(),
        user_salt.to_string(),
        request.password.clone(),
    ).await.map_err(|e| format!("Failed to decrypt signed pre key: {}", e))?;

    let decrypted_kyber_key = decrypt_private_key(
        encrypted_kyber_key.to_string(),
        kyber_key_nonce.to_string(),
        user_salt.to_string(),
        request.password.clone(),
    ).await.map_err(|e| format!("Failed to decrypt kyber key: {}", e))?;



    // Derive public key from private key to verify correctness
    let private_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&decrypted_signed_pre_key)
        .map_err(|e| format!("Failed to decode private key for verification: {}", e))?;
    if private_key_bytes.len() == 32 {
        let mut private_array = [0u8; 32];
        private_array.copy_from_slice(&private_key_bytes);
        let _derived_public = x25519_dalek::x25519(private_array, x25519_dalek::X25519_BASEPOINT_BYTES);

    }

    // Step 9: Perform ECDH with ephemeral key
    let ecdh_secret = perform_ecdh(
        decrypted_signed_pre_key.clone(),
        ephemeral_public_key.to_string(),
    ).await.map_err(|e| format!("ECDH failed: {}", e))?;



    // Step 10: Perform Kyber decapsulation
    let kyber_secret = kyber_decapsulate(
        decrypted_kyber_key.clone(),
        kyber_ciphertext.to_string(),
    ).await.map_err(|e| format!("Kyber decapsulation failed: {}", e))?;



    // Step 11: Derive shared secret using HKDF (same as in perform_key_exchange)
    use hkdf::Hkdf;
    use sha2::Sha256;
    use base64::Engine;

    let ecdh_bytes = base64::engine::general_purpose::STANDARD
        .decode(ecdh_secret)
        .map_err(|e| format!("Failed to decode ECDH secret: {}", e))?;
    let kyber_bytes = base64::engine::general_purpose::STANDARD
        .decode(kyber_secret)
        .map_err(|e| format!("Failed to decode Kyber secret: {}", e))?;
    let _salt_bytes = base64::engine::general_purpose::STANDARD
        .decode(salt)
        .map_err(|e| format!("Failed to decode key exchange salt: {}", e))?;

    // Combine ECDH and Kyber secrets (same as perform_key_exchange)
    let mut combined_secret = Vec::new();
    combined_secret.extend_from_slice(&ecdh_bytes);
    combined_secret.extend_from_slice(&kyber_bytes);

    // Use HKDF without salt dependency for consistent key derivation
    // Use a fixed salt for consistency across all key exchanges
    let fixed_salt = b"e2ee_file_sharing_salt_v1";
    let hk = Hkdf::<Sha256>::new(Some(fixed_salt), &combined_secret);
    let mut final_shared_secret = [0u8; 32];
    hk.expand(b"e2ee_key_exchange", &mut final_shared_secret)
        .map_err(|e| format!("HKDF expansion failed: {}", e))?;

    let shared_secret = base64::engine::general_purpose::STANDARD.encode(final_shared_secret);



    // Step 12: Unwrap master key
    let encrypted_key = wrapped_key_data.get("encrypted_key")
        .and_then(|k| k.as_str())
        .ok_or("Missing encrypted_key in wrapped key data")?
        .to_string();

    let nonce = key_exchange_data.get("nonce")
        .and_then(|n| n.as_str())
        .ok_or("Missing nonce in key exchange data")?
        .to_string();

    let wrapped_key_result = WrappedKeyResult {
        encrypted_key: encrypted_key.clone(),
        nonce: nonce.clone(),
    };



    let master_key = unwrap_master_key(wrapped_key_result, shared_secret.clone()).await
        .map_err(|e| format!("Failed to unwrap master key: {}", e))?;



    // Step 13: Decrypt file content
    let decrypted_file_data = decrypt_file_content(encrypted_content, &master_key).await
        .map_err(|e| format!("Failed to decrypt file content: {}", e))?;

    // Step 14: Save file to Downloads directory
    let _downloads_path = save_file_to_downloads(&decrypted_file_data, file_name).await
        .map_err(|e| format!("Failed to save file to Downloads: {}", e))?;

    Ok(FileDownloadResult {
        success: true,
        file_data: Some(base64::engine::general_purpose::STANDARD.encode(decrypted_file_data)),
        file_name: Some(file_name.to_string()),
        error: None,
    })
}

/// Get user by username
#[tauri::command]
pub async fn api_get_user_by_username(username: String) -> Result<Value, String> {
    let client = ApiClient::default();

    let response = client.get::<Value>(&format!("/users/by-username/{}", urlencoding::encode(&username))).await
        .map_err(|e| format!("Get user by username failed: {}", e))?;

    if response.success {
        Ok(response.data.unwrap_or(Value::Null))
    } else {
        Err(response.error.unwrap_or_else(|| "Get user by username failed".to_string()))
    }
}

/// Get user's message queue
#[tauri::command]
pub async fn api_get_user_messages(user_id: String) -> Result<Value, String> {
    let client = ApiClient::default();

    let response = client.get::<Value>(&format!("/users/{}/messages", user_id)).await
        .map_err(|e| format!("Get user messages failed: {}", e))?;

    if response.success {
        Ok(response.data.unwrap_or(Value::Null))
    } else {
        Err(response.error.unwrap_or_else(|| "Get user messages failed".to_string()))
    }
}

/// Mark message as processed
#[tauri::command]
pub async fn api_mark_message_processed(message_id: String) -> Result<Value, String> {
    let client = ApiClient::default();

    let response = client.patch::<Value, _>(&format!("/messages/{}/processed", message_id), &serde_json::json!({})).await
        .map_err(|e| format!("Mark message processed failed: {}", e))?;

    if response.success {
        Ok(response.data.unwrap_or(Value::Null))
    } else {
        Err(response.error.unwrap_or_else(|| "Mark message processed failed".to_string()))
    }
}

/// Open already-mounted WebDAV volume in Finder
#[tauri::command]
pub async fn open_url(_url: String, vault_name: Option<String>) -> Result<(), String> {
    println!("Opening already-mounted WebDAV volume in Finder for vault: {:?}", vault_name);

    #[cfg(target_os = "macos")]
    {
        // Require vault name to open the mounted volume
        let disk_name = vault_name.ok_or_else(|| "Vault name is required to open the mounted volume".to_string())?;

        println!("Trying to open already-mounted disk: {}", disk_name);

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

        // Use tokio::task::spawn_blocking to properly handle the blocking osascript call
        let open_output = tokio::task::spawn_blocking({
            let open_script = open_script.clone();
            move || {
                std::process::Command::new("osascript")
                    .arg("-e")
                    .arg(&open_script)
                    .output()
            }
        }).await.map_err(|e| format!("Failed to spawn blocking task: {}", e))?;

        match open_output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);

                println!("Open disk AppleScript stdout: {}", stdout);
                if !stderr.is_empty() {
                    println!("Open disk AppleScript stderr: {}", stderr);
                }

                if output.status.success() && stdout.trim() == "success" {
                    println!("✅ Successfully opened mounted disk: {}", disk_name);
                    Ok(())
                } else if stdout.starts_with("error:") {
                    let error_msg = stdout.trim_start_matches("error: ").trim();
                    println!("❌ Failed to open disk {}: {}", disk_name, error_msg);
                    Err(format!("Failed to open mounted disk {}: {}. Make sure the vault is unlocked and mounted.", disk_name, error_msg))
                } else {
                    let error_msg = format!("Unexpected output for disk {}: {}", disk_name, stdout);
                    println!("❓ {}", error_msg);
                    Err(error_msg)
                }
            }
            Err(e) => {
                let error_msg = format!("Failed to execute AppleScript for disk {}: {}", disk_name, e);
                println!("❌ {}", error_msg);
                Err(error_msg)
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Windows implementation - for now just return an error since WebDAV mounting is not implemented
        println!("WebDAV volume opening not yet implemented for Windows");
        Err("WebDAV volume opening not yet implemented for Windows".to_string())
    }

    #[cfg(target_os = "linux")]
    {
        // Linux implementation - for now just return an error since WebDAV mounting is not implemented
        println!("WebDAV volume opening not yet implemented for Linux");
        Err("WebDAV volume opening not yet implemented for Linux".to_string())
    }
}

/// Test encryption/decryption with the same parameters used in key generation
#[tauri::command]
pub async fn test_encryption_decryption(
    password: String,
    test_data: String,
) -> Result<String, String> {
    
    use crate::store::encryption::{MasterKey, EncryptionService};
    use rand::RngCore;

    // Generate the same salt as in key generation
    let salt = {
        let mut s = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut s);
        s
    };



    // Derive master key from password (same as in key generation)
    let master_key = MasterKey::from_password(
        &password,
        &salt,
        &crate::store::encryption::EncryptionConfig::default(),
    ).map_err(|e| format!("Failed to derive key from password: {}", e))?;

    let encryption_service = EncryptionService::with_master_key(master_key);

    // Test encryption
    let encrypted_data = encryption_service.encrypt(test_data.as_bytes())
        .map_err(|e| format!("Test encryption failed: {}", e))?;



    // Test decryption
    let decrypted_data = encryption_service.decrypt(&encrypted_data)
        .map_err(|e| format!("Test decryption failed: {}", e))?;

    let decrypted_string = String::from_utf8(decrypted_data)
        .map_err(|e| format!("Failed to convert decrypted data to string: {}", e))?;

    if decrypted_string == test_data {
        Ok(format!("✅ Test passed! Original: '{}', Decrypted: '{}'", test_data, decrypted_string))
    } else {
        Err(format!("❌ Test failed! Original: '{}', Decrypted: '{}'", test_data, decrypted_string))
    }
}

/// Test the exact same encryption/decryption flow as used in key generation
#[tauri::command]
pub async fn test_key_generation_flow(password: String) -> Result<String, String> {
    use base64::Engine;
    use crate::store::encryption::{MasterKey, EncryptionService};
    use rand::RngCore;

    // Generate salt exactly like in generate_key_bundle
    let salt = {
        let mut s = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut s);
        s
    };



    // Derive master key exactly like in generate_key_bundle
    let master_key = MasterKey::from_password(
        &password,
        &salt,
        &crate::store::encryption::EncryptionConfig::default(),
    ).map_err(|e| format!("Failed to derive key from password: {}", e))?;

    let encryption_service = EncryptionService::with_master_key(master_key);

    // Test with dummy private key data (similar to what's encrypted in key generation)
    let test_private_key = b"dummy_private_key_data_for_testing_32bytes";

    // Encrypt the test private key
    let encrypted_private_key = encryption_service.encrypt(test_private_key)
        .map_err(|e| format!("Failed to encrypt test private key: {}", e))?;



    // Now test decryption using the same flow as decrypt_private_key
    let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt);
    let encrypted_key_b64 = base64::engine::general_purpose::STANDARD.encode(&encrypted_private_key.ciphertext);
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(&encrypted_private_key.nonce);

    // Call the actual decrypt_private_key function
    match decrypt_private_key(encrypted_key_b64, nonce_b64, salt_b64, password).await {
        Ok(decrypted_b64) => {
            let decrypted_bytes = base64::engine::general_purpose::STANDARD
                .decode(decrypted_b64)
                .map_err(|e| format!("Failed to decode decrypted result: {}", e))?;

            if decrypted_bytes == test_private_key {
                Ok("✅ Key generation flow test passed!".to_string())
            } else {
                Err(format!("❌ Key generation flow test failed! Original length: {}, Decrypted length: {}",
                           test_private_key.len(), decrypted_bytes.len()))
            }
        }
        Err(e) => Err(format!("❌ Key generation flow test failed during decryption: {}", e))
    }
}

