use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Argon2, password_hash::Salt};
use base64::Engine;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::error::{StorageError, StorageResult};

/// AES-256-GCM key size in bytes
pub const AES_KEY_SIZE: usize = 32;
/// AES-GCM nonce size in bytes
pub const AES_NONCE_SIZE: usize = 12;
/// Argon2 salt size in bytes
pub const SALT_SIZE: usize = 32;

/// Encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Argon2 memory cost (in KB)
    pub memory_cost: u32,
    /// Argon2 time cost (iterations)
    pub time_cost: u32,
    /// Argon2 parallelism
    pub parallelism: u32,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            memory_cost: 65536, // 64 MB
            time_cost: 3,       // 3 iterations
            parallelism: 4,     // 4 threads
        }
    }
}

/// Encrypted data container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Encrypted ciphertext
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: Vec<u8>,
    /// Salt used for key derivation (if applicable)
    pub salt: Option<Vec<u8>>,
    /// Algorithm identifier
    pub algorithm: String,
}

impl EncryptedData {
    /// Create new encrypted data container
    pub fn new(ciphertext: Vec<u8>, nonce: Vec<u8>, salt: Option<Vec<u8>>) -> Self {
        Self {
            ciphertext,
            nonce,
            salt,
            algorithm: "AES-256-GCM".to_string(),
        }
    }
}

/// Master key for encryption operations
#[derive(Clone)]
pub struct MasterKey {
    key: Secret<[u8; AES_KEY_SIZE]>,
}

impl MasterKey {
    /// Generate a new random master key
    pub fn generate() -> Self {
        let mut key = [0u8; AES_KEY_SIZE];
        key.copy_from_slice(&Aes256Gcm::generate_key(&mut OsRng));
        Self {
            key: Secret::new(key),
        }
    }

    /// Create master key from existing bytes
    pub fn from_bytes(bytes: [u8; AES_KEY_SIZE]) -> Self {
        Self {
            key: Secret::new(bytes),
        }
    }

    /// Derive master key from password using Argon2
    pub fn from_password(
        password: &str,
        salt: &[u8],
        config: &EncryptionConfig,
    ) -> StorageResult<Self> {
        if salt.len() != SALT_SIZE {
            return Err(StorageError::InvalidKeyLength {
                expected: SALT_SIZE,
                actual: salt.len(),
            });
        }

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                config.memory_cost,
                config.time_cost,
                config.parallelism,
                Some(AES_KEY_SIZE),
            )
            .map_err(|e| StorageError::key_derivation(format!("Invalid Argon2 params: {}", e)))?,
        );

        let mut key = [0u8; AES_KEY_SIZE];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| StorageError::key_derivation(format!("Key derivation failed: {}", e)))?;

        Ok(Self {
            key: Secret::new(key),
        })
    }

    /// Get the raw key bytes (use with caution)
    pub fn as_bytes(&self) -> &[u8; AES_KEY_SIZE] {
        self.key.expose_secret()
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        // Zeroize is handled by the Secret wrapper
    }
}

/// Encryption service for secure data storage
#[derive(Clone)]
pub struct EncryptionService {
    master_key: MasterKey,
    config: EncryptionConfig,
}

impl EncryptionService {
    /// Create new encryption service with generated master key
    pub fn new() -> Self {
        Self {
            master_key: MasterKey::generate(),
            config: EncryptionConfig::default(),
        }
    }

    /// Create encryption service with existing master key
    pub fn with_master_key(master_key: MasterKey) -> Self {
        Self {
            master_key,
            config: EncryptionConfig::default(),
        }
    }

    /// Create encryption service with password-derived key
    pub fn with_password(
        password: &str,
        salt: &[u8],
        config: EncryptionConfig,
    ) -> StorageResult<Self> {
        let master_key = MasterKey::from_password(password, salt, &config)?;
        Ok(Self {
            master_key,
            config,
        })
    }

    /// Encrypt data using AES-256-GCM
    pub fn encrypt(&self, plaintext: &[u8]) -> StorageResult<EncryptedData> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.master_key.as_bytes()));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| StorageError::encryption(format!("AES encryption failed: {}", e)))?;

        Ok(EncryptedData::new(
            ciphertext,
            nonce.to_vec(),
            None, // No salt for direct encryption
        ))
    }

    /// Decrypt data using AES-256-GCM
    pub fn decrypt(&self, encrypted_data: &EncryptedData) -> StorageResult<Vec<u8>> {
        if encrypted_data.nonce.len() != AES_NONCE_SIZE {
            return Err(StorageError::InvalidIvLength {
                expected: AES_NONCE_SIZE,
                actual: encrypted_data.nonce.len(),
            });
        }

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.master_key.as_bytes()));
        let nonce = Nonce::from_slice(&encrypted_data.nonce);

        let plaintext = cipher
            .decrypt(nonce, encrypted_data.ciphertext.as_ref())
            .map_err(|e| StorageError::decryption(format!("AES decryption failed: {}", e)))?;

        Ok(plaintext)
    }

    /// Encrypt and serialize data
    pub fn encrypt_serialize<T: Serialize>(&self, data: &T) -> StorageResult<EncryptedData> {
        let json = serde_json::to_vec(data)?;
        self.encrypt(&json)
    }

    /// Decrypt and deserialize data
    pub fn decrypt_deserialize<T: for<'de> Deserialize<'de>>(
        &self,
        encrypted_data: &EncryptedData,
    ) -> StorageResult<T> {
        let json = self.decrypt(encrypted_data)?;
        let data = serde_json::from_slice(&json)?;
        Ok(data)
    }

    /// Generate a random salt for key derivation
    pub fn generate_salt() -> [u8; SALT_SIZE] {
        let mut salt = [0u8; SALT_SIZE];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut salt);
        salt
    }

    /// Get encryption configuration
    pub fn config(&self) -> &EncryptionConfig {
        &self.config
    }
}

impl Default for EncryptionService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_key_generation() {
        let key1 = MasterKey::generate();
        let key2 = MasterKey::generate();

        // Keys should be different
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_password_key_derivation() {
        let password = "test_password";
        let salt = EncryptionService::generate_salt();
        let config = EncryptionConfig::default();

        let key1 = MasterKey::from_password(password, &salt, &config).unwrap();
        let key2 = MasterKey::from_password(password, &salt, &config).unwrap();

        // Same password and salt should produce same key
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_encryption_decryption() {
        let service = EncryptionService::new();
        let plaintext = b"Hello, World!";

        let encrypted = service.encrypt(plaintext).unwrap();
        let decrypted = service.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_serialize_encryption() {
        let service = EncryptionService::new();
        let data = vec!["test", "data", "for", "encryption"];

        let encrypted = service.encrypt_serialize(&data).unwrap();
        let decrypted: Vec<String> = service.decrypt_deserialize(&encrypted).unwrap();

        assert_eq!(data, decrypted);
    }
}
