# Secure File Sharing Data Models

This directory contains comprehensive Rust data models for an end-to-end encrypted file sharing application using Tauri for desktop. The models implement Signal's Sender Key protocol for secure group communication and file sharing.

## Overview

The data models support the complete workflow for secure group file sharing:

1. **User Management** - PQXDH key bundles for post-quantum security
2. **Group Management** - Signal Sender Key protocol for group messaging
3. **File Sharing** - Encrypted file storage and distribution
4. **Error Handling** - Comprehensive error types for all operations

## Core Models

### User Model (`user.rs`)

The `User` struct represents a user in the secure file sharing system:

```rust
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub registration_id: u32,
    pub device_id: u32,
    pub created_at: DateTime<Utc>,
    pub status: UserStatus,
    
    // PQXDH key bundle for post-quantum key exchange
    pub identity_key_pair: Option<KeyPairData>,
    pub signed_pre_key: Option<SignedPreKeyData>,
    pub kyber_pre_key: Option<KyberPreKeyData>,
    pub one_time_pre_keys: Vec<PreKeyData>,
    
    pub group_memberships: HashSet<Uuid>,
    pub preferences: UserPreferences,
}
```

**Key Features:**
- Complete PQXDH key bundle support for post-quantum security
- User status management (Active, Inactive, Suspended, Deleted)
- Group membership tracking
- User preferences for file handling

**Supporting Types:**
- `KeyPairData` - Generic key pair structure
- `SignedPreKeyData` - Signed pre-keys for PQXDH
- `KyberPreKeyData` - Post-quantum Kyber keys
- `PreKeyData` - One-time pre-keys for forward secrecy
- `PublicKeyBundle` - Public keys for key exchange

### Group Model (`group.rs`)

The `Group` struct implements Signal's Sender Key protocol for secure group communication:

```rust
pub struct Group {
    pub id: Uuid,
    pub name: String,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub members: HashSet<Uuid>,
    pub sender_keys: HashMap<Uuid, SenderKeyData>,
    pub shared_files: Vec<SharedFile>,
    pub settings: GroupSettings,
}
```

**Key Features:**
- Signal Sender Key protocol implementation
- Member management with roles and permissions
- Sender key distribution and storage
- Group settings and file retention policies

**Supporting Types:**
- `SenderKeyData` - Signal sender key with chain keys and iterations
- `SenderKeyDistributionMessage` - Key distribution protocol
- `GroupSettings` - Group configuration and limits
- `GroupMember` - Member information with roles
- `GroupRole` - Admin, Member, ReadOnly permissions

### File Model (`file.rs`)

The `SharedFile` struct handles encrypted file sharing within groups:

```rust
pub struct SharedFile {
    pub id: Uuid,
    pub original_name: String,
    pub encrypted_name: String,
    pub size: i64,
    pub mime_type: String,
    pub shared_by: Uuid,
    pub shared_at: DateTime<Utc>,
    pub encryption_metadata: FileEncryptionMetadata,
    pub downloaded_by: HashSet<Uuid>,
    pub status: FileStatus,
    pub description: Option<String>,
    pub storage_path: Option<String>,
}
```

**Key Features:**
- AES-256-GCM encryption with chunked processing
- File integrity verification with checksums
- Download tracking and status management
- MIME type detection and file categorization

**Supporting Types:**
- `FileEncryptionMetadata` - Encryption parameters and keys
- `FileStatus` - Available, Uploading, Failed, Deleted, etc.
- `KeyDerivationParams` - HKDF/PBKDF2 parameters
- `FileShareProgress` - Upload/download progress tracking
- `FileDownloadRequest` - Download request management

### Error Handling (`error.rs`)

Comprehensive error types for all operations:

```rust
pub enum AppError {
    CryptoError(CryptoError),
    FileError(FileError),
    GroupError(GroupError),
    UserError(UserError),
    NetworkError(NetworkError),
    ValidationError(String),
    InternalError(String),
}
```

**Error Categories:**
- `CryptoError` - Key generation, encryption, signature failures
- `FileError` - File I/O, corruption, size limits
- `GroupError` - Membership, permissions, sender keys
- `UserError` - Authentication, account status
- `NetworkError` - Connection, timeout, server errors

## Signal Sender Key Protocol

The implementation follows Signal's Sender Key protocol for efficient group messaging:

1. **Key Generation**: Each user generates a sender key for each group
2. **Key Distribution**: Sender keys are distributed to all group members
3. **Message Encryption**: Files are encrypted using derived keys from sender keys
4. **Forward Secrecy**: Chain keys are advanced with each message

### Key Components

- **Distribution ID**: Unique identifier for sender key distribution
- **Chain ID**: Identifies the key chain for a user in a group
- **Chain Key**: Used to derive message keys for encryption
- **Iteration**: Current position in the key chain
- **Signing Key**: For message authentication

## Usage Examples

### Creating a User with PQXDH Keys

```rust
let mut user = User::new("Alice".to_string());

// Generate identity key pair
user.identity_key_pair = Some(KeyPairData::new(
    public_key_bytes,
    private_key_bytes,
    "Ed25519".to_string(),
));

// Generate signed pre-key
user.signed_pre_key = Some(SignedPreKeyData::new(
    1, // key ID
    public_key_bytes,
    private_key_bytes,
    signature_bytes,
    "X25519".to_string(),
));

// Generate Kyber pre-key for post-quantum security
user.kyber_pre_key = Some(KyberPreKeyData::new(
    1, // key ID
    kyber_public_key,
    kyber_private_key,
    "Kyber1024".to_string(),
));
```

### Creating a Group and Adding Members

```rust
let mut group = Group::new("Research Team".to_string(), creator_id);

// Add members
group.add_member(alice_id);
group.add_member(bob_id);

// Store sender keys for each member
let sender_key = SenderKeyData::new(
    alice_id,
    distribution_id,
    chain_id,
    0, // initial iteration
    chain_key_bytes,
    public_key_bytes,
    Some(private_key_bytes), // Only for own keys
);

group.store_sender_key(alice_id, sender_key);
```

### Sharing an Encrypted File

```rust
let metadata = FileEncryptionMetadata::new(
    encryption_key,
    iv,
    auth_tag,
    1024 * 1024, // 1MB chunks
    total_chunks,
    file_checksum,
);

let shared_file = SharedFile::new(
    "document.pdf".to_string(),
    file_size,
    "application/pdf".to_string(),
    sharer_id,
    metadata,
);

group.add_shared_file(shared_file);
```

## Testing

The models include comprehensive tests in the `demo.rs` module:

```bash
cargo test
```

Tests cover:
- User creation and key bundle validation
- Group management and sender key distribution
- File sharing workflow
- Error handling scenarios

## Security Considerations

1. **Post-Quantum Security**: Uses Kyber for quantum-resistant key exchange
2. **Forward Secrecy**: One-time pre-keys and advancing chain keys
3. **File Integrity**: SHA-256 checksums and AES-GCM authentication
4. **Key Isolation**: Separate sender keys per group
5. **Secure Deletion**: Proper key lifecycle management

## Dependencies

- `serde` - Serialization/deserialization
- `uuid` - Unique identifiers
- `chrono` - Date/time handling
- `rand` - Cryptographic randomness

## Future Enhancements

- Integration with libsignal Node.js bindings
- Database persistence layer
- Network protocol implementation
- File chunking and streaming
- Key rotation mechanisms
