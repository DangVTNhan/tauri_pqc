// Types for E2EE group file sharing system

export interface KeyBundle {
  public_keys: PublicKeyBundle;
  private_keys: PrivateKeyBundle;
  timestamp: string; // ISO string
}

export interface PublicKeyBundle {
  identity_key: string; // Ed25519 public key (base64)
  signed_pre_key: string; // X25519 public key (base64)
  kyber_pre_key: string; // Kyber-768 public key (base64)
  one_time_pre_keys: string[]; // X25519 public keys (base64)
  signature: string; // Ed25519 signature (base64)
}

export interface PrivateKeyBundle {
  identity_key: string; // Encrypted Ed25519 private key (base64)
  signed_pre_key: string; // Encrypted X25519 private key (base64)
  kyber_pre_key: string; // Encrypted Kyber-768 private key (base64)
  one_time_pre_keys: string[]; // Encrypted X25519 private keys (base64)
  salt: string; // Salt for key derivation (base64)
  // Individual nonces for each private key
  identity_key_nonce: string; // Nonce for identity key encryption (base64)
  signed_pre_key_nonce: string; // Nonce for signed pre-key encryption (base64)
  kyber_pre_key_nonce: string; // Nonce for Kyber pre-key encryption (base64)
  one_time_pre_keys_nonces: string[]; // Nonces for one-time pre-keys encryption (base64)
}

export interface User {
  id: string;
  username: string;
  created_at: string; // ISO string
  keyBundle?: KeyBundle; // Optional key bundle for authenticated users
}

export interface UserRegistrationRequest {
  username: string;
  password: string;
  key_bundle: KeyBundle;
}

export interface UserLoginRequest {
  username: string;
  password: string;
}

export interface UserLoginResponse {
  user: User;
  groups: Group[];
}

export interface Group {
  id: string;
  name: string;
  created_by: string;
  created_at: string; // ISO string
  members: string[];
  settings: GroupSettings;
}

export interface GroupSettings {
  max_file_size: number;
  allow_historical_access: boolean;
  allow_member_invites: boolean;
  file_retention_days: number;
}

export interface GroupCreateRequest {
  name: string;
  creator_id: string; // Keep this as creator_id for the API request
}

export interface GroupMemberRequest {
  user_id: string;
}

export interface FileEncryptionMetadata {
  encryption_key: unknown;
  auth_tag: unknown;
  algorithm: string; // e.g., "AES-256-GCM"
  iv: string; // base64 encoded
  chunk_size: number;
  total_chunks: number;
  original_checksum: string; // base64 encoded
  checksum_algorithm: string;
}

export interface WrappedKey {
  encrypted_key: string; // Master key encrypted with derived shared secret (base64)
  key_exchange: KeyExchangeData; // Key exchange data used for this wrapping
}

export interface KeyExchangeData {
  ephemeral_public_key: string; // X25519 ephemeral public key (base64)
  kyber_ciphertext: string; // Kyber-768 ciphertext (base64)
  salt: string; // Salt for KDF (base64)
  nonce: string; // Nonce for key wrapping (base64)
}

export interface SharedFile {
  id: string;
  original_name: string;
  size: number;
  mime_type: string;
  shared_by: string;
  shared_at: string; // ISO string
  group_id: string;
  status: FileStatus;
  blob_url: string; // URL to encrypted blob storage
  blob_hash: string; // SHA-256 hash of encrypted blob
  description?: string;
}

export type FileStatus = 
  | "available" 
  | "uploading" 
  | "upload_failed" 
  | "deleted" 
  | "expired" 
  | "corrupted";

export interface FileShareRequest {
  original_name: string;
  size: number;
  mime_type: string;
  shared_by: string;
  encrypted_content: string; // File encrypted with master key (base64)
  wrapped_master_keys: Record<string, WrappedKey>; // userID -> wrapped master key
  encryption_metadata: FileEncryptionMetadata;
  description?: string;
}

export interface APIResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

// Frontend-specific types
export interface UserSession {
  user: User;
  groups: Group[];
  isAuthenticated: boolean;
}

export interface FileUploadProgress {
  file_name: string;
  progress: number; // 0-100
  status: 'encrypting' | 'uploading' | 'uploading to blob storage' | 'performing key exchange' | 'sending wrapped keys' | 'sharing file metadata' | 'complete' | 'error';
  error?: string;
}

// API Response types
export interface PublicKeyBundleResponse {
  user_id: string;
  username: string;
  public_keys: PublicKeyBundle;
  timestamp: string;
}

export interface FileContentResponse {
  file_id: string;
  encrypted_content: string; // base64 encoded
  wrapped_key: WrappedKey;
  metadata: FileEncryptionMetadata;
  original_name: string;
  mime_type: string;
  size: number;
}
