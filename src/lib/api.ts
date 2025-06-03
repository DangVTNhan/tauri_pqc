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
