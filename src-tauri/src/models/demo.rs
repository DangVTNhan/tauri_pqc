use uuid::Uuid;
use chrono::Utc;

use super::{
    User, Group, SharedFile, FileEncryptionMetadata, SenderKeyData, 
    GroupRole, GroupMember, FileStatus, KeyPairData, SignedPreKeyData,
    KyberPreKeyData, PreKeyData, PublicKeyBundle
};

/// Demo functions to showcase the data models working together
pub struct Demo;

impl Demo {
    /// Create a complete demo scenario with users, groups, and file sharing
    pub fn create_demo_scenario() -> DemoScenario {
        // Create users
        let mut alice = User::new("Alice".to_string());
        let mut bob = User::new("Bob".to_string());
        let mut charlie = User::new("Charlie".to_string());

        // Generate mock key bundles for users
        alice.identity_key_pair = Some(KeyPairData::new(
            vec![1; 32], // Mock public key
            vec![2; 32], // Mock private key
            "Ed25519".to_string(),
        ));
        alice.signed_pre_key = Some(SignedPreKeyData::new(
            1,
            vec![3; 32], // Mock public key
            vec![4; 32], // Mock private key
            vec![5; 64], // Mock signature
            "X25519".to_string(),
        ));
        alice.kyber_pre_key = Some(KyberPreKeyData::new(
            1,
            vec![6; 1568], // Mock Kyber public key
            vec![7; 3168], // Mock Kyber private key
            "Kyber1024".to_string(),
        ));
        alice.one_time_pre_keys.push(PreKeyData::new(
            1,
            vec![8; 32], // Mock public key
            vec![9; 32], // Mock private key
            "X25519".to_string(),
        ));

        // Similar setup for Bob and Charlie (simplified)
        bob.identity_key_pair = Some(KeyPairData::new(
            vec![10; 32], vec![11; 32], "Ed25519".to_string(),
        ));
        bob.signed_pre_key = Some(SignedPreKeyData::new(
            2, vec![12; 32], vec![13; 32], vec![14; 64], "X25519".to_string(),
        ));
        bob.kyber_pre_key = Some(KyberPreKeyData::new(
            2, vec![15; 1568], vec![16; 3168], "Kyber1024".to_string(),
        ));
        bob.one_time_pre_keys.push(PreKeyData::new(
            2, vec![17; 32], vec![18; 32], "X25519".to_string(),
        ));

        charlie.identity_key_pair = Some(KeyPairData::new(
            vec![19; 32], vec![20; 32], "Ed25519".to_string(),
        ));
        charlie.signed_pre_key = Some(SignedPreKeyData::new(
            3, vec![21; 32], vec![22; 32], vec![23; 64], "X25519".to_string(),
        ));
        charlie.kyber_pre_key = Some(KyberPreKeyData::new(
            3, vec![24; 1568], vec![25; 3168], "Kyber1024".to_string(),
        ));
        charlie.one_time_pre_keys.push(PreKeyData::new(
            3, vec![26; 32], vec![27; 32], "X25519".to_string(),
        ));

        // Create a group
        let mut group = Group::new("Research Team".to_string(), alice.id);
        
        // Add members to the group
        group.add_member(bob.id);
        group.add_member(charlie.id);
        
        // Update user group memberships
        alice.join_group(group.id);
        bob.join_group(group.id);
        charlie.join_group(group.id);

        // Create sender keys for each member
        let alice_sender_key = SenderKeyData::new(
            alice.id,
            Uuid::new_v4(),
            12345,
            0,
            vec![28; 32], // Mock chain key
            vec![29; 32], // Mock public key
            Some(vec![30; 32]), // Mock private key (Alice's own key)
        );

        let bob_sender_key = SenderKeyData::new(
            bob.id,
            Uuid::new_v4(),
            12346,
            0,
            vec![31; 32], // Mock chain key
            vec![32; 32], // Mock public key
            None, // No private key (not Bob's own key from Alice's perspective)
        );

        let charlie_sender_key = SenderKeyData::new(
            charlie.id,
            Uuid::new_v4(),
            12347,
            0,
            vec![33; 32], // Mock chain key
            vec![34; 32], // Mock public key
            None, // No private key (not Charlie's own key from Alice's perspective)
        );

        // Store sender keys in the group
        group.store_sender_key(alice.id, alice_sender_key);
        group.store_sender_key(bob.id, bob_sender_key);
        group.store_sender_key(charlie.id, charlie_sender_key);

        // Create some shared files
        let file1_metadata = FileEncryptionMetadata::new(
            vec![35; 32], // Encryption key
            vec![36; 12], // IV
            vec![37; 16], // Auth tag
            1024 * 1024,  // 1MB chunk size
            5,            // 5 chunks
            vec![38; 32], // Original checksum
        );

        let file1 = SharedFile::new(
            "research_paper.pdf".to_string(),
            5 * 1024 * 1024, // 5MB file
            "application/pdf".to_string(),
            alice.id,
            file1_metadata,
        );

        let file2_metadata = FileEncryptionMetadata::new(
            vec![39; 32], // Encryption key
            vec![40; 12], // IV
            vec![41; 16], // Auth tag
            512 * 1024,   // 512KB chunk size
            10,           // 10 chunks
            vec![42; 32], // Original checksum
        );

        let mut file2 = SharedFile::new(
            "presentation.pptx".to_string(),
            5 * 1024 * 1024, // 5MB file
            "application/vnd.openxmlformats-officedocument.presentationml.presentation".to_string(),
            bob.id,
            file2_metadata,
        );

        // Mark file2 as downloaded by Alice
        file2.mark_downloaded_by(alice.id);

        // Add files to the group
        group.add_shared_file(file1);
        group.add_shared_file(file2);

        DemoScenario {
            users: vec![alice, bob, charlie],
            group,
        }
    }

    /// Demonstrate key bundle validation
    pub fn validate_key_bundles(scenario: &DemoScenario) -> Vec<(String, bool)> {
        scenario.users.iter().map(|user| {
            let has_complete_bundle = user.has_complete_key_bundle();
            let bundle_valid = if let Some(bundle) = user.get_public_key_bundle() {
                bundle.validate().is_ok()
            } else {
                false
            };
            (user.name.clone(), has_complete_bundle && bundle_valid)
        }).collect()
    }

    /// Demonstrate file sharing workflow
    pub fn demonstrate_file_sharing(scenario: &DemoScenario) -> FileShareSummary {
        let total_files = scenario.group.shared_files.len();
        let total_size: i64 = scenario.group.shared_files.iter().map(|f| f.size).sum();
        let available_files = scenario.group.shared_files.iter()
            .filter(|f| f.is_available())
            .count();
        
        let download_stats: Vec<(String, usize)> = scenario.group.shared_files.iter()
            .map(|f| (f.original_name.clone(), f.download_count()))
            .collect();

        FileShareSummary {
            total_files,
            total_size,
            available_files,
            download_stats,
        }
    }

    /// Demonstrate sender key management
    pub fn demonstrate_sender_keys(scenario: &DemoScenario) -> SenderKeysSummary {
        let total_keys = scenario.group.sender_keys.len();
        let own_keys = scenario.group.sender_keys.values()
            .filter(|key| key.is_own_key())
            .count();
        
        let key_details: Vec<(String, u32, u32)> = scenario.users.iter()
            .filter_map(|user| {
                scenario.group.get_sender_key(&user.id).map(|key| {
                    (user.name.clone(), key.chain_id, key.iteration)
                })
            })
            .collect();

        SenderKeysSummary {
            total_keys,
            own_keys,
            key_details,
        }
    }
}

/// Complete demo scenario with users and group
pub struct DemoScenario {
    pub users: Vec<User>,
    pub group: Group,
}

/// Summary of file sharing statistics
pub struct FileShareSummary {
    pub total_files: usize,
    pub total_size: i64,
    pub available_files: usize,
    pub download_stats: Vec<(String, usize)>,
}

/// Summary of sender key statistics
pub struct SenderKeysSummary {
    pub total_keys: usize,
    pub own_keys: usize,
    pub key_details: Vec<(String, u32, u32)>, // (user_name, chain_id, iteration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_demo_scenario_creation() {
        let scenario = Demo::create_demo_scenario();
        
        // Verify users
        assert_eq!(scenario.users.len(), 3);
        assert!(scenario.users.iter().all(|u| u.has_complete_key_bundle()));
        
        // Verify group
        assert_eq!(scenario.group.members.len(), 3);
        assert_eq!(scenario.group.sender_keys.len(), 3);
        assert_eq!(scenario.group.shared_files.len(), 2);
    }

    #[test]
    fn test_key_bundle_validation() {
        let scenario = Demo::create_demo_scenario();
        let validations = Demo::validate_key_bundles(&scenario);
        
        assert_eq!(validations.len(), 3);
        assert!(validations.iter().all(|(_, valid)| *valid));
    }

    #[test]
    fn test_file_sharing_demo() {
        let scenario = Demo::create_demo_scenario();
        let summary = Demo::demonstrate_file_sharing(&scenario);
        
        assert_eq!(summary.total_files, 2);
        assert_eq!(summary.available_files, 2);
        assert!(summary.total_size > 0);
    }

    #[test]
    fn test_sender_keys_demo() {
        let scenario = Demo::create_demo_scenario();
        let summary = Demo::demonstrate_sender_keys(&scenario);
        
        assert_eq!(summary.total_keys, 3);
        assert_eq!(summary.own_keys, 1); // Only Alice has her own private key
        assert_eq!(summary.key_details.len(), 3);
    }
}
