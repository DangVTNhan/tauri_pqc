// API utilities for communicating with Go backend

import type {
    APIResponse,
    FileContentResponse,
    FileShareRequest,
    Group,
    GroupCreateRequest,
    GroupMemberRequest,
    PublicKeyBundleResponse,
    SharedFile,
    User,
    UserLoginRequest,
    UserLoginResponse,
    UserRegistrationRequest,
    WrappedKey
} from '@/types/e2ee';


const API_BASE_URL = 'http://localhost:8080';

class APIClient {
  private baseUrl: string;

  constructor(baseUrl: string = API_BASE_URL) {
    this.baseUrl = baseUrl;
  }

  private async request<T>(
    endpoint: string, 
    options: RequestInit = {}
  ): Promise<APIResponse<T>> {
    const url = `${this.baseUrl}${endpoint}`;
    
    const defaultHeaders = {
      'Content-Type': 'application/json',
    };

    try {
      const response = await fetch(url, {
        ...options,
        headers: {
          ...defaultHeaders,
          ...options.headers,
        },
      });

      const data = await response.json();
      
      if (!response.ok) {
        return {
          success: false,
          error: data.error || `HTTP ${response.status}: ${response.statusText}`,
        };
      }

      return data;
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Network error occurred',
      };
    }
  }

  // Health check
  async healthCheck(): Promise<APIResponse<{ status: string; service: string; version: string }>> {
    return this.request('/health');
  }

  // User registration
  async registerUser(request: UserRegistrationRequest): Promise<APIResponse<User>> {
    return this.request('/register', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // User login
  async loginUser(request: UserLoginRequest): Promise<APIResponse<UserLoginResponse>> {
    return this.request('/login', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // Get user by username
  async getUserByUsername(username: string): Promise<APIResponse<User>> {
    return this.request(`/users/by-username/${encodeURIComponent(username)}`);
  }

  // Upload encrypted blob to storage
  async uploadBlob(encryptedContent: string): Promise<APIResponse<{
    blob_id: string;
    blob_url: string;
    blob_hash: string;
    size: number;
  }>> {
    // Calculate hash of the base64-decoded binary data
    const binaryData = Uint8Array.from(atob(encryptedContent), c => c.charCodeAt(0));
    const hashBuffer = await crypto.subtle.digest('SHA-256', binaryData);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return this.request('/blobs/upload', {
      method: 'POST',
      body: JSON.stringify({
        encrypted_content: encryptedContent,
        blob_hash: hashHex,
      }),
    });
  }

  // Send bulk wrapped keys to multiple users
  async sendBulkWrappedKeys(
    fileId: string,
    groupId: string,
    wrappedKeys: Record<string, WrappedKey>
  ): Promise<APIResponse<{
    file_id: string;
    group_id: string;
    sent_messages: string[];
    failed_recipients: string[];
    total_sent: number;
    total_failed: number;
  }>> {
    return this.request('/messages/send-bulk', {
      method: 'POST',
      body: JSON.stringify({
        file_id: fileId,
        group_id: groupId,
        wrapped_keys: wrappedKeys,
      }),
    });
  }

  // Group operations
  async createGroup(request: GroupCreateRequest): Promise<APIResponse<Group>> {
    return this.request('/groups', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async addGroupMember(groupId: string, request: GroupMemberRequest): Promise<APIResponse<any>> {
    return this.request(`/groups/${groupId}/members`, {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // File operations
  async shareFile(groupId: string, request: FileShareRequest): Promise<APIResponse<SharedFile>> {
    return this.request(`/groups/${groupId}/files`, {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // Share file metadata only (zero-knowledge)
  async shareFileMetadata(groupId: string, request: {
    original_name: string;
    size: number;
    mime_type: string;
    shared_by: string;
    blob_url: string;
    blob_hash: string;
    description?: string;
  }): Promise<APIResponse<SharedFile>> {
    return this.request(`/groups/${groupId}/files`, {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async getGroupFiles(groupId: string): Promise<APIResponse<{ group_id: string; files: SharedFile[] }>> {
    return this.request(`/groups/${groupId}/files`);
  }

  // Get public key bundles for multiple users
  async getPublicKeyBundles(userIds: string[]): Promise<APIResponse<{ public_key_bundles: PublicKeyBundleResponse[] }>> {
    return this.request('/public-key-bundles', {
      method: 'POST',
      body: JSON.stringify({ user_ids: userIds }),
    });
  }

  // Add wrapped keys for a new group member
  async addWrappedKeysForNewMember(groupId: string, userId: string, wrappedKeys: Record<string, WrappedKey>): Promise<APIResponse<any>> {
    return this.request(`/groups/${groupId}/wrapped-keys`, {
      method: 'POST',
      body: JSON.stringify({
        user_id: userId,
        wrapped_keys: wrappedKeys,
      }),
    });
  }

  // Get file content and wrapped key for a user
  async getFileContent(fileId: string, userId: string): Promise<APIResponse<FileContentResponse>> {
    return this.request(`/files/${fileId}/content?user_id=${encodeURIComponent(userId)}`);
  }

  // Get user's message queue
  async getUserMessages(userId: string): Promise<APIResponse<{
    user_id: string;
    messages: any[];
    count: number;
  }>> {
    return this.request(`/users/${userId}/messages`);
  }

  // Download encrypted blob from storage
  async downloadBlob(blobUrl: string): Promise<APIResponse<{
    blob_id: string;
    encrypted_content: string;
    blob_hash: string;
    size: number;
  }>> {
    // Extract blob ID from URL (e.g., "/blobs/abc123" -> "abc123")
    const blobId = blobUrl.split('/').pop();
    return this.request(`/blobs/${blobId}`);
  }

  // Mark message as processed
  async markMessageProcessed(messageId: string): Promise<APIResponse<{
    message_id: string;
    processed: boolean;
  }>> {
    return this.request(`/messages/${messageId}/processed`, {
      method: 'PATCH',
    });
  }
}

export const apiClient = new APIClient();

// Utility functions for common API operations
export const api = {
  // Check if backend is available
  async isBackendAvailable(): Promise<boolean> {
    try {
      const response = await apiClient.healthCheck();
      return response.success;
    } catch {
      return false;
    }
  },

  // Register a new user
  async register(username: string, password: string, keyBundle: any): Promise<{ success: boolean; user?: User; error?: string }> {
    const response = await apiClient.registerUser({
      username,
      password,
      key_bundle: keyBundle,
    });

    if (response.success && response.data) {
      return { success: true, user: response.data };
    }

    return { success: false, error: response.error };
  },

  // Login a user
  async login(username: string, password: string): Promise<{ success: boolean; user?: User; groups?: Group[]; error?: string }> {
    const response = await apiClient.loginUser({
      username,
      password,
    });

    if (response.success && response.data) {
      return {
        success: true,
        user: response.data.user,
        groups: response.data.groups
      };
    }

    return { success: false, error: response.error };
  },

  // Get user by username
  async getUserByUsername(username: string): Promise<{ success: boolean; user?: User; error?: string }> {
    const response = await apiClient.getUserByUsername(username);

    if (response.success && response.data) {
      return { success: true, user: response.data };
    }

    return { success: false, error: response.error };
  },

  // Upload encrypted blob to storage
  async uploadBlob(encryptedContent: string): Promise<{ success: boolean; data?: any; error?: string }> {
    const response = await apiClient.uploadBlob(encryptedContent);

    if (response.success && response.data) {
      return { success: true, data: response.data };
    }

    return { success: false, error: response.error };
  },

  // Send bulk wrapped keys to multiple users
  async sendBulkWrappedKeys(
    fileId: string,
    groupId: string,
    wrappedKeys: Record<string, WrappedKey>
  ): Promise<{ success: boolean; data?: any; error?: string }> {
    const response = await apiClient.sendBulkWrappedKeys(fileId, groupId, wrappedKeys);

    if (response.success && response.data) {
      return { success: true, data: response.data };
    }

    return { success: false, error: response.error };
  },

  // Share file metadata only (zero-knowledge)
  async shareFileMetadata(
    groupId: string,
    file: File,
    blobUrl: string,
    blobHash: string,
    sharedBy: string
  ): Promise<{ success: boolean; file?: SharedFile; error?: string }> {
    const request = {
      original_name: file.name,
      size: file.size,
      mime_type: file.type,
      shared_by: sharedBy,
      blob_url: blobUrl,
      blob_hash: blobHash,
    };

    const response = await apiClient.shareFileMetadata(groupId, request);

    if (response.success && response.data) {
      return { success: true, file: response.data };
    }

    return { success: false, error: response.error };
  },

  // Get user's message queue
  async getUserMessages(userId: string): Promise<{ success: boolean; data?: any; error?: string }> {
    const response = await apiClient.getUserMessages(userId);

    if (response.success && response.data) {
      return { success: true, data: response.data };
    }

    return { success: false, error: response.error };
  },

  // Download encrypted blob from storage
  async downloadBlob(blobUrl: string): Promise<{ success: boolean; data?: any; error?: string }> {
    const response = await apiClient.downloadBlob(blobUrl);

    if (response.success && response.data) {
      return { success: true, data: response.data };
    }

    return { success: false, error: response.error };
  },

  // Mark message as processed
  async markMessageProcessed(messageId: string): Promise<{ success: boolean; error?: string }> {
    const response = await apiClient.markMessageProcessed(messageId);

    if (response.success) {
      return { success: true };
    }

    return { success: false, error: response.error };
  },

  // Create a new group
  async createGroup(name: string, creatorId: string): Promise<{ success: boolean; group?: Group; error?: string }> {
    const response = await apiClient.createGroup({
      name,
      creator_id: creatorId,
    });

    if (response.success && response.data) {
      return { success: true, group: response.data };
    }

    return { success: false, error: response.error };
  },

  // Add member to group
  async addMember(groupId: string, userId: string): Promise<{ success: boolean; error?: string }> {
    const response = await apiClient.addGroupMember(groupId, { user_id: userId });
    
    if (response.success) {
      return { success: true };
    }

    return { success: false, error: response.error };
  },

  // Share a file in a group with wrapped master keys
  async shareFile(
    groupId: string,
    file: File,
    encryptedContent: string,
    wrappedMasterKeys: Record<string, WrappedKey>,
    encryptionMetadata: any,
    sharedBy: string
  ): Promise<{ success: boolean; file?: SharedFile; error?: string }> {
    const request: FileShareRequest = {
      original_name: file.name,
      size: file.size,
      mime_type: file.type || 'application/octet-stream',
      shared_by: sharedBy,
      encrypted_content: encryptedContent,
      wrapped_master_keys: wrappedMasterKeys,
      encryption_metadata: encryptionMetadata,
    };

    const response = await apiClient.shareFile(groupId, request);

    if (response.success && response.data) {
      return { success: true, file: response.data };
    }

    return { success: false, error: response.error };
  },

  // Get public key bundles for users
  async getPublicKeyBundles(userIds: string[]): Promise<{ success: boolean; bundles?: PublicKeyBundleResponse[]; error?: string }> {
    const response = await apiClient.getPublicKeyBundles(userIds);

    if (response.success && response.data) {
      return { success: true, bundles: response.data.public_key_bundles };
    }

    return { success: false, error: response.error };
  },

  // Add wrapped keys for a new group member
  async addWrappedKeysForNewMember(
    groupId: string,
    userId: string,
    wrappedKeys: Record<string, WrappedKey>
  ): Promise<{ success: boolean; error?: string }> {
    const response = await apiClient.addWrappedKeysForNewMember(groupId, userId, wrappedKeys);

    if (response.success) {
      return { success: true };
    }

    return { success: false, error: response.error };
  },

  // Get file content and wrapped key for download
  async getFileContent(fileId: string, userId: string): Promise<{ success: boolean; content?: FileContentResponse; error?: string }> {
    const response = await apiClient.getFileContent(fileId, userId);

    if (response.success && response.data) {
      return { success: true, content: response.data };
    }

    return { success: false, error: response.error };
  },

  // Get files in a group
  async getGroupFiles(groupId: string): Promise<{ success: boolean; files?: SharedFile[]; error?: string }> {
    try {
      const response = await apiClient.getGroupFiles(groupId);
      console.log('Raw API response for getGroupFiles:', response);

      if (response.success && response.data) {
        return { success: true, files: response.data.files };
      }

      return { success: false, error: response.error };
    } catch (error) {
      console.error('Exception in getGroupFiles:', error);
      return { success: false, error: error instanceof Error ? error.message : 'Network error' };
    }
  },
};
