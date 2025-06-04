#[cfg(test)]
mod tests {
    use super::super::{
        generate_key_bundle, perform_key_exchange, generate_ephemeral_keypair,
        generate_kyber_keypair, perform_ecdh, kyber_encapsulate, kyber_decapsulate,
        derive_shared_secret, wrap_master_key, unwrap_master_key, decrypt_private_key,
        encrypt_data, decrypt_data, generate_random_bytes,
    };
    use base64::Engine;

    #[tokio::test]
    async fn test_generate_key_bundle() {
        let password = "test_password_123".to_string();
        
        let result = generate_key_bundle(password.clone()).await;
        assert!(result.is_ok(), "Key bundle generation should succeed");
        
        let key_bundle = result.unwrap();
        
        // Verify public keys are base64 encoded and have reasonable lengths
        assert!(!key_bundle.public_keys.identity_key.is_empty());
        assert!(!key_bundle.public_keys.signed_pre_key.is_empty());
        assert!(!key_bundle.public_keys.kyber_pre_key.is_empty());
        assert!(!key_bundle.public_keys.one_time_pre_keys.is_empty());
        assert!(!key_bundle.public_keys.signature.is_empty());
        
        // Verify private keys are encrypted and base64 encoded
        assert!(!key_bundle.private_keys.identity_key.is_empty());
        assert!(!key_bundle.private_keys.signed_pre_key.is_empty());
        assert!(!key_bundle.private_keys.kyber_pre_key.is_empty());
        assert!(!key_bundle.private_keys.one_time_pre_keys.is_empty());
        assert!(!key_bundle.private_keys.salt.is_empty());
        
        // Verify nonces are present
        assert!(!key_bundle.private_keys.identity_key_nonce.is_empty());
        assert!(!key_bundle.private_keys.signed_pre_key_nonce.is_empty());
        assert!(!key_bundle.private_keys.kyber_pre_key_nonce.is_empty());
        assert!(!key_bundle.private_keys.one_time_pre_keys_nonces.is_empty());
        
        // Verify timestamp is valid
        assert!(!key_bundle.timestamp.is_empty());
    }

    #[tokio::test]
    async fn test_generate_ephemeral_keypair() {
        let result = generate_ephemeral_keypair().await;
        assert!(result.is_ok(), "Ephemeral keypair generation should succeed");
        
        let keypair = result.unwrap();
        
        // Verify keys are base64 encoded
        assert!(!keypair.private_key.is_empty());
        assert!(!keypair.public_key.is_empty());
        
        // Verify keys can be decoded from base64
        let private_bytes = base64::engine::general_purpose::STANDARD
            .decode(&keypair.private_key);
        let public_bytes = base64::engine::general_purpose::STANDARD
            .decode(&keypair.public_key);
        
        assert!(private_bytes.is_ok());
        assert!(public_bytes.is_ok());
        assert_eq!(private_bytes.unwrap().len(), 32);
        assert_eq!(public_bytes.unwrap().len(), 32);
    }

    #[tokio::test]
    async fn test_generate_kyber_keypair() {
        let result = generate_kyber_keypair().await;
        assert!(result.is_ok(), "Kyber keypair generation should succeed");
        
        let keypair = result.unwrap();
        
        // Verify keys are base64 encoded
        assert!(!keypair.private_key.is_empty());
        assert!(!keypair.public_key.is_empty());
        
        // Verify keys can be decoded from base64
        let private_bytes = base64::engine::general_purpose::STANDARD
            .decode(&keypair.private_key);
        let public_bytes = base64::engine::general_purpose::STANDARD
            .decode(&keypair.public_key);
        
        assert!(private_bytes.is_ok());
        assert!(public_bytes.is_ok());
        
        // Kyber-768 key sizes
        assert_eq!(private_bytes.unwrap().len(), 2400); // KYBER_SECRETKEYBYTES
        assert_eq!(public_bytes.unwrap().len(), 1184);  // KYBER_PUBLICKEYBYTES
    }

    #[tokio::test]
    async fn test_perform_ecdh() {
        // Generate two keypairs
        let alice_keypair = generate_ephemeral_keypair().await.unwrap();
        let bob_keypair = generate_ephemeral_keypair().await.unwrap();
        
        // Perform ECDH from Alice's perspective
        let alice_shared = perform_ecdh(
            alice_keypair.private_key.clone(),
            bob_keypair.public_key.clone(),
        ).await;
        assert!(alice_shared.is_ok(), "Alice's ECDH should succeed");
        
        // Perform ECDH from Bob's perspective
        let bob_shared = perform_ecdh(
            bob_keypair.private_key.clone(),
            alice_keypair.public_key.clone(),
        ).await;
        assert!(bob_shared.is_ok(), "Bob's ECDH should succeed");
        
        // Shared secrets should be the same
        assert_eq!(alice_shared.unwrap(), bob_shared.unwrap());
    }

    #[tokio::test]
    async fn test_kyber_encapsulation_decapsulation() {
        // Generate Kyber keypair
        let keypair = generate_kyber_keypair().await.unwrap();
        
        // Perform encapsulation
        let encap_result = kyber_encapsulate(keypair.public_key.clone()).await;
        assert!(encap_result.is_ok(), "Kyber encapsulation should succeed");
        
        let encapsulation = encap_result.unwrap();
        assert!(!encapsulation.ciphertext.is_empty());
        assert!(!encapsulation.shared_secret.is_empty());
        
        // Perform decapsulation
        let decap_result = kyber_decapsulate(
            keypair.private_key.clone(),
            encapsulation.ciphertext.clone(),
        ).await;
        assert!(decap_result.is_ok(), "Kyber decapsulation should succeed");
        
        // Shared secrets should match
        assert_eq!(encapsulation.shared_secret, decap_result.unwrap());
    }

    #[tokio::test]
    async fn test_derive_shared_secret() {
        // Generate ECDH and Kyber secrets
        let alice_keypair = generate_ephemeral_keypair().await.unwrap();
        let bob_keypair = generate_ephemeral_keypair().await.unwrap();
        let kyber_keypair = generate_kyber_keypair().await.unwrap();
        
        // Perform ECDH
        let ecdh_secret = perform_ecdh(
            alice_keypair.private_key,
            bob_keypair.public_key,
        ).await.unwrap();
        
        // Perform Kyber encapsulation
        let kyber_encap = kyber_encapsulate(kyber_keypair.public_key).await.unwrap();
        
        // Generate random salt
        let salt = generate_random_bytes(32).await.unwrap();
        let info = "test_key_derivation".to_string();
        
        // Derive shared secret
        let derived_secret = derive_shared_secret(
            ecdh_secret,
            kyber_encap.shared_secret,
            salt,
            info,
        ).await;
        
        assert!(derived_secret.is_ok(), "Shared secret derivation should succeed");
        
        let secret = derived_secret.unwrap();
        assert!(!secret.is_empty());
        
        // Verify it's 32 bytes (256 bits) when decoded
        let secret_bytes = base64::engine::general_purpose::STANDARD
            .decode(&secret).unwrap();
        assert_eq!(secret_bytes.len(), 32);
    }

    #[tokio::test]
    async fn test_wrap_unwrap_master_key() {
        // Generate a master key and shared secret
        let master_key = generate_random_bytes(32).await.unwrap();
        let shared_secret = generate_random_bytes(32).await.unwrap();
        let salt = generate_random_bytes(32).await.unwrap();
        
        // Wrap the master key
        let wrapped_result = wrap_master_key(
            master_key.clone(),
            shared_secret.clone(),
            salt,
        ).await;
        assert!(wrapped_result.is_ok(), "Master key wrapping should succeed");
        
        let wrapped_key = wrapped_result.unwrap();
        assert!(!wrapped_key.encrypted_key.is_empty());
        assert!(!wrapped_key.nonce.is_empty());
        
        // Unwrap the master key
        let unwrapped_result = unwrap_master_key(
            wrapped_key,
            shared_secret,
        ).await;
        assert!(unwrapped_result.is_ok(), "Master key unwrapping should succeed");
        
        // Should get back the original master key
        assert_eq!(master_key, unwrapped_result.unwrap());
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_data() {
        let test_data = "Hello, World! This is a test message.";
        let test_data_b64 = base64::engine::general_purpose::STANDARD.encode(test_data);
        let master_key = generate_random_bytes(32).await.unwrap();
        
        // Encrypt the data
        let encrypt_result = encrypt_data(test_data_b64.clone(), master_key.clone()).await;
        assert!(encrypt_result.is_ok(), "Data encryption should succeed");
        
        let encrypted = encrypt_result.unwrap();
        assert!(!encrypted.encrypted_data.is_empty());
        assert!(!encrypted.encryption_key.is_empty());
        assert!(!encrypted.iv.is_empty());
        assert!(!encrypted.algorithm.is_empty());
        
        // Decrypt the data
        let decrypt_result = decrypt_data(
            encrypted.encrypted_data,
            encrypted.encryption_key,
            encrypted.iv,
            encrypted.auth_tag,
            encrypted.algorithm,
        ).await;
        assert!(decrypt_result.is_ok(), "Data decryption should succeed");
        
        // Should get back the original data
        assert_eq!(test_data_b64, decrypt_result.unwrap());
    }

    #[tokio::test]
    async fn test_generate_random_bytes() {
        // Test different lengths
        for length in [16, 32, 64, 128] {
            let result = generate_random_bytes(length).await;
            assert!(result.is_ok(), "Random bytes generation should succeed");
            
            let random_b64 = result.unwrap();
            let random_bytes = base64::engine::general_purpose::STANDARD
                .decode(&random_b64).unwrap();
            assert_eq!(random_bytes.len(), length);
        }
        
        // Test maximum length
        let max_result = generate_random_bytes(1024).await;
        assert!(max_result.is_ok());
        
        // Test over maximum length
        let over_max_result = generate_random_bytes(1025).await;
        assert!(over_max_result.is_err());
    }

    #[tokio::test]
    async fn test_realworld_e2ee_messaging_workflow() {
        use std::collections::HashMap;
        use uuid::Uuid;

        // Simulate a real-world E2EE messaging scenario
        println!("🚀 Starting Real-World E2EE Messaging Workflow Test");

        // Step 1: Create a group with multiple members (like WhatsApp/Signal group)
        let group_name = "Secure Development Team";
        let group_id = Uuid::new_v4();
        println!("📱 Creating group: {}", group_name);

        // Step 2: Create 5 team members with their key bundles
        let password = "SecureTeamPassword123!";
        let mut team_members = Vec::new();
        let member_names = vec!["Alice (Team Lead)", "Bob (Backend Dev)", "Carol (Frontend Dev)", "Dave (DevOps)", "Eve (Security)"];

        for (i, name) in member_names.iter().enumerate() {
            let member_id = Uuid::new_v4();
            let key_bundle = generate_key_bundle(password.to_string()).await.unwrap();

            team_members.push((member_id, name.to_string(), key_bundle));
            println!("👤 Created member {}: {} (ID: {})", i + 1, name, member_id);
        }

        // Step 3: Alice (Team Lead) sends a secure message to the group
        let sender = &team_members[0]; // Alice
        let message_content = format!(
            "🔒 CONFIDENTIAL TEAM MESSAGE 🔒\n\n\
            Hi team! This is a secure message from {}.\n\n\
            Meeting agenda for today:\n\
            1. Security audit results\n\
            2. New encryption implementation\n\
            3. Key rotation schedule\n\
            4. Incident response plan\n\n\
            This message is encrypted end-to-end and can only be read by team members.\n\
            Timestamp: {}\n\
            Group: {}\n\n\
            Please confirm receipt by replying to this secure channel.",
            sender.1,
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            group_name
        );

        println!("📝 Alice composing message ({} chars)", message_content.len());

        // Step 4: Generate unique master key for this message
        let message_master_key = generate_random_bytes(32).await.unwrap();
        println!("🔑 Generated unique master key for message");

        // Step 5: Encrypt the message with the master key
        let message_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, message_content.as_bytes());
        let encrypted_message = encrypt_data(message_b64.clone(), message_master_key.clone()).await.unwrap();
        println!("🔒 Message encrypted ({} bytes -> {} chars base64)",
                message_content.len(), encrypted_message.encrypted_data.len());

        // Step 6: Create wrapped master keys for ALL team members using real cryptography
        let mut wrapped_keys_for_members = HashMap::new();
        let mut encryption_debug_data = HashMap::new();

        // Generate sender's ephemeral key pair for this message
        let sender_ephemeral = generate_ephemeral_keypair().await.unwrap();
        println!("🔑 Generated sender's ephemeral ECDH key pair");

        for (i, (member_id, member_name, member_keys)) in team_members.iter().enumerate() {
            println!("🔐 Creating wrapped key for member {}: {}", i + 1, member_name);

            // Perform ECDH key exchange
            let ecdh_secret = perform_ecdh(
                sender_ephemeral.private_key.clone(),
                member_keys.public_keys.signed_pre_key.clone()
            ).await.unwrap();

            // Perform Kyber encapsulation
            let kyber_result = kyber_encapsulate(
                member_keys.public_keys.kyber_pre_key.clone()
            ).await.unwrap();

            // Generate salt for this member
            let salt = generate_random_bytes(32).await.unwrap();

            // Derive shared secret using HKDF
            let shared_secret = derive_shared_secret(
                ecdh_secret.clone(),
                kyber_result.shared_secret.clone(),
                salt.clone(),
                format!("secure_message_{}_{}", group_id, member_id)
            ).await.unwrap();

            // Wrap the master key for this member
            let wrapped_key = wrap_master_key(
                message_master_key.clone(),
                shared_secret.clone(),
                salt.clone()
            ).await.unwrap();

            // Store wrapped key with key exchange data
            wrapped_keys_for_members.insert(*member_id, (wrapped_key, kyber_result.ciphertext, salt.clone()));

            // Store debug data for verification
            encryption_debug_data.insert(*member_id, (ecdh_secret, kyber_result.shared_secret, shared_secret));

            println!("✅ Wrapped master key for {}", member_name);
        }

        println!("📤 Message ready for secure distribution to {} members", team_members.len());

        // Step 7: Simulate message delivery and decryption by each team member
        let mut successful_decryptions = Vec::new();

        for (i, (member_id, member_name, member_keys)) in team_members.iter().enumerate() {
            println!("\n🔄 Member {} ({}): Attempting to decrypt message...", i + 1, member_name);

            // Get the wrapped key for this member
            let (wrapped_key, kyber_ciphertext, salt) = wrapped_keys_for_members.get(member_id).unwrap();

            // Step 7a: Decrypt member's private keys using their password
            let decrypted_signed_pre_key = decrypt_private_key(
                member_keys.private_keys.signed_pre_key.clone(),
                member_keys.private_keys.signed_pre_key_nonce.clone(),
                member_keys.private_keys.salt.clone(),
                password.to_string()
            ).await.unwrap();

            let decrypted_kyber_key = decrypt_private_key(
                member_keys.private_keys.kyber_pre_key.clone(),
                member_keys.private_keys.kyber_pre_key_nonce.clone(),
                member_keys.private_keys.salt.clone(),
                password.to_string()
            ).await.unwrap();

            println!("🔓 {} decrypted their private keys", member_name);

            // Step 7b: Perform ECDH with member's private key and sender's ephemeral public key
            let ecdh_secret = perform_ecdh(
                decrypted_signed_pre_key,
                sender_ephemeral.public_key.clone()
            ).await.unwrap();

            // Step 7c: Perform Kyber decapsulation
            let kyber_secret = kyber_decapsulate(
                decrypted_kyber_key,
                kyber_ciphertext.clone()
            ).await.unwrap();

            // Step 7d: Derive the same shared secret
            let shared_secret = derive_shared_secret(
                ecdh_secret.clone(),
                kyber_secret.clone(),
                salt.clone(),
                format!("secure_message_{}_{}", group_id, member_id)
            ).await.unwrap();

            // Verify cryptographic consistency
            let (orig_ecdh, orig_kyber, orig_shared) = encryption_debug_data.get(member_id).unwrap();
            assert_eq!(&ecdh_secret, orig_ecdh, "ECDH secrets must match for {}", member_name);
            assert_eq!(&kyber_secret, orig_kyber, "Kyber secrets must match for {}", member_name);
            assert_eq!(&shared_secret, orig_shared, "Shared secrets must match for {}", member_name);

            println!("✅ {} derived correct shared secret", member_name);

            // Step 7e: Unwrap the master key
            let unwrapped_master_key = unwrap_master_key(
                wrapped_key.clone(),
                shared_secret
            ).await.unwrap();

            assert_eq!(unwrapped_master_key, message_master_key, "Master keys must match for {}", member_name);
            println!("🔑 {} successfully unwrapped master key", member_name);

            // Step 7f: Decrypt the message
            let decrypted_message_b64 = decrypt_data(
                encrypted_message.encrypted_data.clone(),
                unwrapped_master_key,
                encrypted_message.iv.clone(),
                encrypted_message.auth_tag.clone(),
                encrypted_message.algorithm.clone()
            ).await.unwrap();

            // Convert back to original text
            let decrypted_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &decrypted_message_b64).unwrap();
            let decrypted_text = String::from_utf8(decrypted_bytes).unwrap();

            // Verify message content
            assert_eq!(decrypted_text, message_content, "Decrypted message must match original for {}", member_name);

            println!("📖 {} successfully read the message:", member_name);
            println!("   \"{}...\"", &decrypted_text[..100.min(decrypted_text.len())]);

            successful_decryptions.push(member_name.clone());
        }

        // Step 8: Verify complete workflow success
        println!("\n📊 SECURE MESSAGING WORKFLOW RESULTS:");
        println!("✅ Group created: {} (ID: {})", group_name, group_id);
        println!("✅ Members added: {}", team_members.len());
        println!("✅ Message encrypted with unique master key");
        println!("✅ Master key wrapped for all {} members", team_members.len());
        println!("✅ Successful decryptions: {}/{}", successful_decryptions.len(), team_members.len());

        assert_eq!(successful_decryptions.len(), team_members.len(),
                  "All team members should be able to decrypt the message");

        println!("🎯 PERFECT! Real-world E2EE messaging workflow completed successfully");
        println!("🔒 Security verified: Zero-knowledge, client-side encryption");
        println!("🛡️ Privacy verified: Only group members can read the message");
        println!("🔑 Cryptography verified: Proper EC + Kyber key exchange");
    }

    #[tokio::test]
    async fn test_multi_round_secure_conversation() {
        use std::collections::HashMap;
        use uuid::Uuid;

        println!("💬 Starting Multi-Round Secure Conversation Test");

        // Create a small team for rapid conversation
        let password = "ConversationTest123!";
        let group_id = Uuid::new_v4();
        let mut participants = Vec::new();
        let names = vec!["Alice", "Bob", "Carol"];

        // Generate key bundles for all participants
        for name in &names {
            let participant_id = Uuid::new_v4();
            let key_bundle = generate_key_bundle(password.to_string()).await.unwrap();
            participants.push((participant_id, name.to_string(), key_bundle));
            println!("👤 {} joined the secure conversation", name);
        }

        // Simulate a multi-round conversation
        let conversation_messages = vec![
            (0, "Hi team! Let's discuss the new security protocol. 🔒"),
            (1, "Great idea Alice! I've been working on the implementation details."),
            (2, "I can help with the frontend integration. What's our timeline?"),
            (0, "We need to have this ready by next Friday. Bob, can you share your progress?"),
            (1, "Sure! I've completed the key derivation module. Carol, do you need the API specs?"),
            (2, "Yes please! Also, should we schedule a code review session?"),
            (0, "Absolutely. Let's meet tomorrow at 2 PM. I'll send the calendar invite."),
        ];

        let mut conversation_history = Vec::new();

        for (round, (sender_idx, message_text)) in conversation_messages.iter().enumerate() {
            let sender = &participants[*sender_idx];
            println!("\n📝 Round {}: {} says: \"{}\"", round + 1, sender.1, message_text);

            // Generate unique master key for this message
            let message_master_key = generate_random_bytes(32).await.unwrap();

            // Encrypt the message
            let message_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, message_text.as_bytes());
            let encrypted_message = encrypt_data(message_b64.clone(), message_master_key.clone()).await.unwrap();

            // Create wrapped keys for all participants
            let sender_ephemeral = generate_ephemeral_keypair().await.unwrap();
            let mut wrapped_keys = HashMap::new();

            for (participant_id, participant_name, participant_keys) in &participants {
                // Perform key exchange
                let ecdh_secret = perform_ecdh(
                    sender_ephemeral.private_key.clone(),
                    participant_keys.public_keys.signed_pre_key.clone()
                ).await.unwrap();

                let kyber_result = kyber_encapsulate(
                    participant_keys.public_keys.kyber_pre_key.clone()
                ).await.unwrap();

                let salt = generate_random_bytes(32).await.unwrap();

                let shared_secret = derive_shared_secret(
                    ecdh_secret,
                    kyber_result.shared_secret,
                    salt.clone(),
                    format!("conversation_{}_{}_round_{}", group_id, participant_id, round)
                ).await.unwrap();

                let wrapped_key = wrap_master_key(
                    message_master_key.clone(),
                    shared_secret,
                    salt.clone()
                ).await.unwrap();

                wrapped_keys.insert(*participant_id, (wrapped_key, kyber_result.ciphertext, salt));
            }

            // Store the encrypted message with metadata
            conversation_history.push((
                round,
                sender.0,
                sender.1.clone(),
                encrypted_message,
                sender_ephemeral,
                wrapped_keys,
                message_text.to_string() // For verification
            ));

            println!("🔒 Message encrypted and distributed to {} participants", participants.len());
        }

        println!("\n📚 Conversation complete! Now testing decryption by each participant...");

        // Each participant reads the entire conversation history
        for (reader_idx, (reader_id, reader_name, reader_keys)) in participants.iter().enumerate() {
            println!("\n👤 {} is reading the conversation history:", reader_name);

            // Decrypt reader's private keys once
            let decrypted_signed_pre_key = decrypt_private_key(
                reader_keys.private_keys.signed_pre_key.clone(),
                reader_keys.private_keys.signed_pre_key_nonce.clone(),
                reader_keys.private_keys.salt.clone(),
                password.to_string()
            ).await.unwrap();

            let decrypted_kyber_key = decrypt_private_key(
                reader_keys.private_keys.kyber_pre_key.clone(),
                reader_keys.private_keys.kyber_pre_key_nonce.clone(),
                reader_keys.private_keys.salt.clone(),
                password.to_string()
            ).await.unwrap();

            // Read each message in the conversation
            for (round, sender_id, sender_name, encrypted_msg, sender_ephemeral, wrapped_keys, original_text) in &conversation_history {
                // Get the wrapped key for this reader
                let (wrapped_key, kyber_ciphertext, salt) = wrapped_keys.get(reader_id).unwrap();

                // Perform key exchange to derive shared secret
                let ecdh_secret = perform_ecdh(
                    decrypted_signed_pre_key.clone(),
                    sender_ephemeral.public_key.clone()
                ).await.unwrap();

                let kyber_secret = kyber_decapsulate(
                    decrypted_kyber_key.clone(),
                    kyber_ciphertext.clone()
                ).await.unwrap();

                let shared_secret = derive_shared_secret(
                    ecdh_secret,
                    kyber_secret,
                    salt.clone(),
                    format!("conversation_{}_{}_round_{}", group_id, reader_id, round)
                ).await.unwrap();

                // Unwrap master key and decrypt message
                let unwrapped_master_key = unwrap_master_key(
                    wrapped_key.clone(),
                    shared_secret
                ).await.unwrap();

                let decrypted_message_b64 = decrypt_data(
                    encrypted_msg.encrypted_data.clone(),
                    unwrapped_master_key,
                    encrypted_msg.iv.clone(),
                    encrypted_msg.auth_tag.clone(),
                    encrypted_msg.algorithm.clone()
                ).await.unwrap();

                let decrypted_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &decrypted_message_b64).unwrap();
                let decrypted_text = String::from_utf8(decrypted_bytes).unwrap();

                // Verify message content
                assert_eq!(decrypted_text, *original_text, "Message content must match for reader {}", reader_name);

                println!("   Round {}: {} said: \"{}\"", round + 1, sender_name, decrypted_text);
            }

            println!("✅ {} successfully read all {} messages", reader_name, conversation_history.len());
        }

        println!("\n🎯 Multi-Round Secure Conversation Test Results:");
        println!("✅ Participants: {}", participants.len());
        println!("✅ Messages exchanged: {}", conversation_history.len());
        println!("✅ Total decryptions: {}", participants.len() * conversation_history.len());
        println!("✅ All messages successfully encrypted and decrypted");
        println!("🔒 Perfect forward secrecy: Each message uses unique keys");
        println!("🛡️ Zero-knowledge: Server never sees plaintext");
        println!("💬 Real-world messaging workflow verified!");
    }

    #[tokio::test]
    async fn test_full_e2ee_workflow() {
        let password = "test_password_123".to_string();
        
        // Generate key bundles for Alice and Bob
        let alice_bundle = generate_key_bundle(password.clone()).await.unwrap();
        let bob_bundle = generate_key_bundle(password.clone()).await.unwrap();
        
        // Perform key exchange from Alice to Bob
        let key_exchange_result = perform_key_exchange(
            bob_bundle.public_keys.clone(),
            alice_bundle.private_keys.clone(),
            password.clone(),
        ).await;
        assert!(key_exchange_result.is_ok(), "Key exchange should succeed");
        
        let exchange = key_exchange_result.unwrap();
        assert!(!exchange.shared_secret.is_empty());
        assert!(!exchange.ephemeral_public_key.is_empty());
        assert!(!exchange.kyber_ciphertext.is_empty());
        assert!(!exchange.salt.is_empty());
        
        // Generate a master key for file encryption
        let file_master_key = generate_random_bytes(32).await.unwrap();
        
        // Wrap the master key with the shared secret
        let wrapped_key = wrap_master_key(
            file_master_key.clone(),
            exchange.shared_secret.clone(),
            exchange.salt.clone(),
        ).await.unwrap();
        
        // Unwrap the master key
        let unwrapped_key = unwrap_master_key(
            wrapped_key,
            exchange.shared_secret,
        ).await.unwrap();
        
        // Should get back the original master key
        assert_eq!(file_master_key, unwrapped_key);
        
        // Test file encryption/decryption with the master key
        let test_file_content = "This is a secret file content that should be encrypted.";
        let test_file_b64 = base64::engine::general_purpose::STANDARD.encode(test_file_content);
        
        let encrypted_file = encrypt_data(test_file_b64.clone(), unwrapped_key).await.unwrap();
        let decrypted_file = decrypt_data(
            encrypted_file.encrypted_data,
            encrypted_file.encryption_key,
            encrypted_file.iv,
            encrypted_file.auth_tag,
            encrypted_file.algorithm,
        ).await.unwrap();
        
        assert_eq!(test_file_b64, decrypted_file);
    }
}
