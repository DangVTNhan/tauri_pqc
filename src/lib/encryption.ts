// Encryption utilities using Tauri's encryption APIs

import type {
  FileEncryptionMetadata,
  KeyBundle,
  KeyExchangeData,
  PrivateKeyBundle,
  PublicKeyBundle,
  WrappedKey
} from '@/types/e2ee';
import { invoke } from '@tauri-apps/api/core';

// Generate a random key bundle for E2EE using Tauri
export async function generateKeyBundle(password: string): Promise<KeyBundle> {
  try {
    const result = await invoke<{
      public_keys: PublicKeyBundle;
      private_keys: PrivateKeyBundle;
      timestamp: string;
    }>('generate_key_bundle', { password });

    return {
      public_keys: result.public_keys,
      private_keys: result.private_keys,
      timestamp: result.timestamp,
    };
  } catch (error) {
    console.error('Failed to generate key bundle:', error);
    throw new Error('Failed to generate E2EE key bundle');
  }
}

// Perform key exchange to derive shared secret
export async function performKeyExchange(
  recipientPublicKeys: PublicKeyBundle,
  senderPrivateKeys: PrivateKeyBundle,
  password: string
): Promise<{
  sharedSecret: string;
  keyExchangeData: KeyExchangeData;
}> {
  try {
    const result = await invoke<{
      shared_secret: string;
      ephemeral_public_key: string;
      kyber_ciphertext: string;
      salt: string;
    }>('perform_key_exchange', {
      recipientPublicKeys,
      senderPrivateKeys,
      password,
    });

    return {
      sharedSecret: result.shared_secret,
      keyExchangeData: {
        ephemeral_public_key: result.ephemeral_public_key,
        kyber_ciphertext: result.kyber_ciphertext,
        salt: result.salt,
        nonce: '', // Will be set during key wrapping
      },
    };
  } catch (error) {
    console.error('Failed to perform key exchange:', error);
    throw new Error('Failed to perform key exchange');
  }
}

// Wrap (encrypt) a master key using a shared secret
export async function wrapMasterKey(
  masterKey: string,
  sharedSecret: string,
  salt: string
): Promise<WrappedKey> {
  try {
    const result = await invoke<{
      encrypted_key: string;
      nonce: string;
    }>('wrap_master_key', {
      masterKey,
      sharedSecret,
      salt,
    });

    return {
      encrypted_key: result.encrypted_key,
      key_exchange: {
        ephemeral_public_key: '', // Set by caller
        kyber_ciphertext: '',     // Set by caller
        salt,
        nonce: result.nonce,
      },
    };
  } catch (error) {
    console.error('Failed to wrap master key:', error);
    throw new Error('Failed to wrap master key');
  }
}

// Unwrap (decrypt) a master key using a shared secret
export async function unwrapMasterKey(
  wrappedKey: WrappedKey,
  sharedSecret: string
): Promise<string> {
  try {
    const result = await invoke<string>('unwrap_master_key', {
      wrappedKey: {
        encrypted_key: wrappedKey.encrypted_key,
        nonce: wrappedKey.key_exchange.nonce,
      },
      sharedSecret,
    });

    return result;
  } catch (error) {
    console.error('Failed to unwrap master key:', error);
    throw new Error('Failed to unwrap master key');
  }
}

// Generate a random master key for file encryption
export function generateMasterKey(): string {
  const keyBytes = new Uint8Array(32); // 256-bit key
  crypto.getRandomValues(keyBytes);
  return arrayBufferToBase64(keyBytes.buffer);
}

// Encrypt file data with a master key
export async function encryptFileWithMasterKey(
  fileData: ArrayBuffer,
  masterKey: string
): Promise<{
  encryptedData: string;
  metadata: FileEncryptionMetadata;
}> {
  try {
    // Convert ArrayBuffer to base64 for Tauri
    const base64Data = arrayBufferToBase64(fileData);

    // Call Tauri encryption command with the master key
    const result = await invoke<{
      encrypted_data: string;
      encryption_key: string;
      iv: string;
      auth_tag: string;
      algorithm: string;
    }>('encrypt_data', {
      data: base64Data,
      masterKey: masterKey,
    });

    // Generate additional metadata
    const chunkSize = 4096; // 4KB chunks
    const totalChunks = Math.ceil(fileData.byteLength / chunkSize);
    const checksum = await generateChecksum(fileData);

    const metadata: FileEncryptionMetadata = {
      algorithm: result.algorithm,
      iv: result.iv,
      chunk_size: chunkSize,
      total_chunks: totalChunks,
      original_checksum: checksum,
      checksum_algorithm: 'SHA-256',
      encryption_key: undefined,
      auth_tag: undefined
    };

    return {
      encryptedData: result.encrypted_data,
      metadata,
    };
  } catch (error) {
    console.error('Failed to encrypt file:', error);
    throw new Error('Failed to encrypt file data');
  }
}

// Decrypt file data using Tauri's encryption service
export async function decryptFile(
  encryptedData: string,
  metadata: FileEncryptionMetadata
): Promise<ArrayBuffer> {
  try {
    // Call Tauri decryption command
    const decryptedBase64 = await invoke<string>('decrypt_data', {
      encryptedData,
      encryptionKey: metadata.encryption_key,
      iv: metadata.iv,
      authTag: metadata.auth_tag,
      algorithm: metadata.algorithm,
    });

    // Convert base64 back to ArrayBuffer
    const decryptedData = base64ToArrayBuffer(decryptedBase64);

    // Verify checksum
    const checksum = await generateChecksum(decryptedData);
    if (checksum !== metadata.original_checksum) {
      throw new Error('File integrity check failed');
    }

    return decryptedData;
  } catch (error) {
    console.error('Failed to decrypt file:', error);
    throw new Error('Failed to decrypt file data');
  }
}

// Generate SHA-256 checksum of data
async function generateChecksum(data: ArrayBuffer): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return arrayBufferToBase64(hashBuffer);
}

// Convert ArrayBuffer to base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Convert base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// Read file as ArrayBuffer
export function readFileAsArrayBuffer(file: File): Promise<ArrayBuffer> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      if (reader.result instanceof ArrayBuffer) {
        resolve(reader.result);
      } else {
        reject(new Error('Failed to read file as ArrayBuffer'));
      }
    };
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
}

// Create downloadable blob from decrypted data
export function createDownloadBlob(data: ArrayBuffer, mimeType: string): Blob {
  return new Blob([data], { type: mimeType });
}

// Trigger file download
export function downloadFile(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// New cryptographic functions using real Tauri backend operations

// Generate ephemeral ECDH key pair
export async function generateEphemeralKeypair(): Promise<{
  privateKey: string;
  publicKey: string;
}> {
  try {
    const result = await invoke<{
      private_key: string;
      public_key: string;
    }>('generate_ephemeral_keypair');

    return {
      privateKey: result.private_key,
      publicKey: result.public_key,
    };
  } catch (error) {
    console.error('Failed to generate ephemeral keypair:', error);
    throw new Error('Failed to generate ephemeral keypair');
  }
}

// Generate Kyber key pair
export async function generateKyberKeypair(): Promise<{
  privateKey: string;
  publicKey: string;
}> {
  try {
    const result = await invoke<{
      private_key: string;
      public_key: string;
    }>('generate_kyber_keypair');

    return {
      privateKey: result.private_key,
      publicKey: result.public_key,
    };
  } catch (error) {
    console.error('Failed to generate Kyber keypair:', error);
    throw new Error('Failed to generate Kyber keypair');
  }
}

// Perform ECDH key exchange
export async function performECDH(
  privateKey: string,
  publicKey: string
): Promise<string> {
  try {
    const result = await invoke<string>('perform_ecdh', {
      privateKey,
      publicKey,
    });

    return result;
  } catch (error) {
    console.error('Failed to perform ECDH:', error);
    throw new Error('Failed to perform ECDH');
  }
}

// Perform Kyber encapsulation
export async function kyberEncapsulate(publicKey: string): Promise<{
  ciphertext: string;
  sharedSecret: string;
}> {
  try {
    const result = await invoke<{
      ciphertext: string;
      shared_secret: string;
    }>('kyber_encapsulate', {
      publicKey,
    });

    return {
      ciphertext: result.ciphertext,
      sharedSecret: result.shared_secret,
    };
  } catch (error) {
    console.error('Failed to perform Kyber encapsulation:', error);
    throw new Error('Failed to perform Kyber encapsulation');
  }
}

// Perform Kyber decapsulation
export async function kyberDecapsulate(
  privateKey: string,
  ciphertext: string
): Promise<string> {
  try {
    const result = await invoke<string>('kyber_decapsulate', {
      privateKey,
      ciphertext,
    });

    return result;
  } catch (error) {
    console.error('Failed to perform Kyber decapsulation:', error);
    throw new Error('Failed to perform Kyber decapsulation');
  }
}

// Derive shared secret using HKDF
export async function deriveSharedSecret(
  ecdhSecret: string,
  kyberSecret: string,
  salt: string,
  info: string
): Promise<string> {
  try {
    const result = await invoke<string>('derive_shared_secret', {
      ecdhSecret,
      kyberSecret,
      salt,
      info,
    });

    return result;
  } catch (error) {
    console.error('Failed to derive shared secret:', error);
    throw new Error('Failed to derive shared secret');
  }
}

// Generate cryptographically secure random bytes
export async function generateRandomBytes(length: number): Promise<string> {
  try {
    const result = await invoke<string>('generate_random_bytes', {
      length,
    });

    return result;
  } catch (error) {
    console.error('Failed to generate random bytes:', error);
    throw new Error('Failed to generate random bytes');
  }
}
