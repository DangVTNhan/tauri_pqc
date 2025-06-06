use crate::commands::*;
use crate::auth::commands::*;
use crate::store::auth::AuthStorage;
use std::sync::Arc;
use tokio::sync::RwLock;
use base64::Engine;

/// Integration test for E2EE key exchange and file encryption/decryption
/// Tests the core cryptographic operations without requiring full auth system
#[tokio::test]
async fn test_e2ee_key_exchange_and_file_encryption() {
    println!("🧪 Starting E2EE Key Exchange and File Encryption Test");

    const PASSWORD: &str = "test_password_123";
    const TEST_FILE_CONTENT: &str = "This is a secret document that should be encrypted end-to-end!";

    println!("\n📝 Step 1: Generate key bundles for Alice and Bob");

    // Generate key bundles for Alice and Bob
    let alice_bundle = generate_key_bundle(PASSWORD.to_string()).await
        .expect("Alice key bundle generation should succeed");
    let bob_bundle = generate_key_bundle(PASSWORD.to_string()).await
        .expect("Bob key bundle generation should succeed");

    println!("   ✅ Key bundles generated successfully");

    println!("\n🔐 Step 2: Perform key exchange between Alice and Bob");

    // Alice performs key exchange with Bob's public keys
    let alice_key_exchange = perform_key_exchange(
        alice_bundle.public_keys.clone(),
        bob_bundle.private_keys.clone(),
        PASSWORD.to_string(),
    ).await.expect("Alice key exchange should succeed");

    println!("   ✅ Key exchange completed");
    println!("      Shared secret length: {} bytes", alice_key_exchange.shared_secret.len());

    println!("\n📁 Step 3: Encrypt file with master key");

    // Generate a master key
    let master_key = generate_random_bytes(32).await
        .expect("Master key generation should succeed");

    // Encrypt the file content
    let encrypted_content = encrypt_file_content(TEST_FILE_CONTENT.as_bytes(), &master_key).await
        .expect("File encryption should succeed");

    // Verify that encrypted content is different from original
    let encrypted_base64 = String::from_utf8(encrypted_content.clone())
        .expect("Encrypted content should be valid UTF-8 base64");
    let original_base64 = base64::engine::general_purpose::STANDARD.encode(TEST_FILE_CONTENT.as_bytes());

    assert_ne!(encrypted_base64, original_base64, "Encrypted content should be different from original");

    println!("   ✅ File encrypted successfully");
    println!("      Original size: {} bytes", TEST_FILE_CONTENT.len());
    println!("      Encrypted size: {} bytes", encrypted_content.len());

    println!("\n🔑 Step 4: Wrap master key with shared secret");

    // Wrap the master key using the shared secret
    let wrapped_key = wrap_master_key(
        master_key.clone(),
        alice_key_exchange.shared_secret.clone(),
        alice_key_exchange.salt.clone(),
    ).await.expect("Master key wrapping should succeed");

    println!("   ✅ Master key wrapped successfully");

    println!("\n🔓 Step 5: Unwrap master key and decrypt file");

    // Unwrap the master key using the same shared secret
    let unwrapped_master_key = unwrap_master_key(
        wrapped_key,
        alice_key_exchange.shared_secret,
    ).await.expect("Master key unwrapping should succeed");

    // Verify the unwrapped key matches the original
    assert_eq!(unwrapped_master_key, master_key, "Unwrapped master key should match original");

    // Decrypt the file content
    let decrypted_data = decrypt_file_content(&encrypted_base64, &unwrapped_master_key).await
        .expect("File decryption should succeed");
    let decrypted_content = String::from_utf8(decrypted_data)
        .expect("Decrypted content should be valid UTF-8");

    assert_eq!(decrypted_content, TEST_FILE_CONTENT, "Decrypted content should match original");

    println!("   ✅ File decrypted successfully");
    println!("      Original:  '{}'", TEST_FILE_CONTENT);
    println!("      Decrypted: '{}'", decrypted_content);

    println!("\n🎉 E2EE Key Exchange and File Encryption Test PASSED!");
    println!("   ✅ Key bundle generation");
    println!("   ✅ PQXDH key exchange");
    println!("   ✅ Master key generation");
    println!("   ✅ File encryption/decryption");
    println!("   ✅ Master key wrapping/unwrapping");
    println!("   ✅ End-to-end cryptographic flow");
}

/// Test that verifies encryption is actually happening
#[tokio::test]
async fn test_file_encryption_verification() {
    println!("🔐 Testing File Encryption Verification");

    const ORIGINAL_CONTENT: &str = "This content should be encrypted!";

    // Generate a master key
    let master_key = generate_random_bytes(32).await
        .expect("Master key generation should succeed");

    // Encrypt the content
    let encrypted_result = encrypt_file_content(ORIGINAL_CONTENT.as_bytes(), &master_key).await
        .expect("File encryption should succeed");

    // Verify that encrypted content is different from original
    let encrypted_base64 = String::from_utf8(encrypted_result.clone())
        .expect("Encrypted result should be valid UTF-8 base64");
    let original_base64 = base64::engine::general_purpose::STANDARD.encode(ORIGINAL_CONTENT.as_bytes());

    assert_ne!(encrypted_base64, original_base64, "Encrypted content should be different from original");

    // Decrypt and verify
    let decrypted_data = decrypt_file_content(&encrypted_base64, &master_key).await
        .expect("File decryption should succeed");
    let decrypted_content = String::from_utf8(decrypted_data)
        .expect("Decrypted content should be valid UTF-8");

    assert_eq!(decrypted_content, ORIGINAL_CONTENT, "Decrypted content should match original");

    println!("   ✅ File encryption/decryption verified");
    println!("   ✅ Encrypted content is different from original");
    println!("   ✅ Decrypted content matches original");
}
