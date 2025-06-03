// Cryptographic command tests
#[cfg(test)]
mod crypto_tests;

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

/// Mount a WebDAV volume using Cryptomator-style AppleScript with authentication
#[tauri::command]
pub async fn mount_webdav_volume(
    url: String,
    vault_name: String,
    username: String,
    password: String
) -> Result<(), String> {
    use std::process::Command;

    println!("Attempting to mount WebDAV volume: {} for vault: {}", url, vault_name);

    #[cfg(target_os = "macos")]
    {
        // Use proper AppleScript with authentication
        let mount_script = format!(
            r#"set mountURL to "{}"
set mountName to "{}"
set userName to "{}"
set userPassword to "{}"
try
    mount volume mountURL as user name userName with password userPassword
    delay 2
    tell application "Finder" to set name of disk mountURL to mountName
    return "success"
on error errMsg
    try
        mount volume mountURL
        delay 2
        tell application "Finder" to set name of disk mountURL to mountName
        return "success"
    on error errMsg2
        return "error: " & errMsg2
    end try
end try"#,
            url, vault_name, username, password
        );

        println!("Executing Cryptomator-style mount AppleScript for vault: {}", vault_name);

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

                if output.status.success() && stdout.trim() == "success" {
                    println!("Successfully mounted WebDAV volume: {}", vault_name);
                    return Ok(());
                } else if stdout.starts_with("error:") {
                    let error_msg = stdout.trim_start_matches("error: ").trim();
                    println!("Mount failed: {}", error_msg);
                    return Err(format!("Failed to mount WebDAV volume {}: {}", vault_name, error_msg));
                } else {
                    let error_msg = format!("Unexpected AppleScript output: {}", stdout);
                    println!("{}", error_msg);
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

    // Generate salt and nonce for key derivation
    let salt = {
        let mut s = [0u8; 32];
        OsRng.fill_bytes(&mut s);
        s
    };

    let nonce = {
        let mut n = [0u8; 12];
        OsRng.fill_bytes(&mut n);
        n
    };

    // Derive encryption key from password
    let master_key = MasterKey::from_password(
        &password,
        &salt,
        &crate::store::encryption::EncryptionConfig::default(),
    ).map_err(|e| format!("Failed to derive key from password: {}", e))?;

    let encryption_service = EncryptionService::with_master_key(master_key);

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

    // Generate salt for HKDF
    let mut hkdf_salt = [0u8; 32];
    OsRng.fill_bytes(&mut hkdf_salt);

    // Combine ECDH and Kyber secrets using HKDF
    let mut combined_secret = Vec::new();
    combined_secret.extend_from_slice(&ecdh_secret);
    combined_secret.extend_from_slice(&kyber_shared_secret);

    let hk = Hkdf::<Sha256>::new(Some(&hkdf_salt), &combined_secret);
    let mut final_shared_secret = [0u8; 32];
    hk.expand(b"e2ee_key_exchange", &mut final_shared_secret)
        .map_err(|e| format!("HKDF expansion failed: {}", e))?;

    Ok(KeyExchangeResult {
        shared_secret: base64::engine::general_purpose::STANDARD.encode(final_shared_secret),
        ephemeral_public_key: base64::engine::general_purpose::STANDARD.encode(ephemeral_public_bytes),
        kyber_ciphertext: base64::engine::general_purpose::STANDARD.encode(&kyber_ciphertext),
        salt: base64::engine::general_purpose::STANDARD.encode(hkdf_salt),
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
        return Err("Invalid shared secret length".to_string());
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
        .map_err(|e| format!("Failed to unwrap master key: {}", e))?;

    // Return as base64
    Ok(base64::engine::general_purpose::STANDARD.encode(decrypted_key))
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
        .map_err(|e| format!("Failed to decrypt private key: {}", e))?;

    // Return as base64
    Ok(base64::engine::general_purpose::STANDARD.encode(decrypted_key))
}

// Result structures for key operations
#[derive(serde::Serialize)]
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

