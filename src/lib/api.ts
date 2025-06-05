// API utilities for communicating with Go backend through Tauri commands
// This maintains zero-knowledge E2EE architecture by routing all API calls through Rust backend

import { invoke } from '@tauri-apps/api/core';
import type {
    APIResponse,
    FileContentResponse,
    Group,
    GroupCreateRequest,
    GroupMemberRequest,
    PublicKeyBundleResponse,
    SharedFile,
    User,
    WrappedKey
} from '@/types/e2ee';

// Authentication API functions
export const authApi = {
  // Register a new user
  async register(username: string, password: string): Promise<{ success: boolean; user?: User; error?: string }> {
    try {
      const response = await invoke<any>('auth_register', { username, password });
      return { success: true, user: response.user };
    } catch (error) {
      return { success: false, error: error as string };
    }
  },

  // Login user
  async login(username: string, password: string): Promise<{ success: boolean; user?: User; groups?: Group[]; error?: string }> {
    try {
      const response = await invoke<any>('auth_login', { username, password });
      return {
        success: true,
        user: response.user,
        groups: response.groups
      };
    } catch (error) {
      return { success: false, error: error as string };
    }
  },

  // Logout current user
  async logout(): Promise<{ success: boolean; error?: string }> {
    try {
      await invoke('auth_logout');
      return { success: true };
    } catch (error) {
      return { success: false, error: error as string };
    }
  },

  // Check if user is logged in
  async isLoggedIn(): Promise<boolean> {
    try {
      return await invoke<boolean>('auth_is_logged_in');
    } catch {
      return false;
    }
  },

  // Get current user session
  async getCurrentSession(): Promise<any | null> {
    try {
      return await invoke<any>('auth_get_current_session');
    } catch {
      return null;
    }
  },

  // Get current user
  async getCurrentUser(): Promise<any | null> {
    try {
      return await invoke<any>('auth_get_current_user');
    } catch {
      return null;
    }
  },
};

class APIClient {
  // Health check
  async healthCheck(): Promise<APIResponse<{ status: string; service: string; version: string }>> {
    try {
      const data = await invoke<any>('api_health_check');
      return { success: true, data };
    } catch (error) {
      return { success: false, error: error as string };
    }
  }

  // Upload encrypted blob to storage
  async uploadBlob(encryptedContent: string): Promise<APIResponse<{
    blob_id: string;
    blob_url: string;
    blob_hash: string;
    size: number;
  }>> {
    try {
      const data = await invoke<any>('api_upload_blob', { encryptedContent });
      return { success: true, data };
    } catch (error) {
      return { success: false, error: error as string };
    }
  }

  // Get user by username
  async getUserByUsername(username: string): Promise<APIResponse<User>> {
    try {
      const data = await invoke<any>('api_get_user_by_username', { username });
      return { success: true, data };
    } catch (error) {
      return { success: false, error: error as string };
    }
  }

  // Download encrypted blob from storage
  async downloadBlob(blobUrl: string): Promise<APIResponse<{
    blob_id: string;
    encrypted_content: string;
    blob_hash: string;
    size: number;
  }>> {
    try {
      const data = await invoke<any>('api_download_blob', { blobUrl });
      return { success: true, data };
    } catch (error) {
      return { success: false, error: error as string };
    }
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
    try {
      const data = await invoke<any>('api_send_bulk_wrapped_keys', {
        fileId,
        groupId,
        wrappedKeys
      });
      return { success: true, data };
    } catch (error) {
      return { success: false, error: error as string };
    }
  }

  // Group operations
  async createGroup(request: GroupCreateRequest): Promise<APIResponse<Group>> {
    try {
      const data = await invoke<any>('api_create_group', {
        name: request.name,
        creatorId: request.creator_id
      });
      return { success: true, data };
    } catch (error) {
      return { success: false, error: error as string };
    }
  }

  async addGroupMember(groupId: string, request: GroupMemberRequest): Promise<APIResponse<any>> {
    try {
      const data = await invoke<any>('api_add_group_member', {
        groupId,
        userId: request.user_id
      });
      return { success: true, data };
    } catch (error) {
      return { success: false, error: error as string };
    }
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
    try {
      const data = await invoke<any>('api_share_file_metadata', {
        groupId,
        originalName: request.original_name,
        size: request.size,
        mimeType: request.mime_type,
        sharedBy: request.shared_by,
        blobUrl: request.blob_url,
        blobHash: request.blob_hash,
        description: request.description,
      });
      return { success: true, data };
    } catch (error) {
      return { success: false, error: error as string };
    }
  }

  async getGroupFiles(groupId: string): Promise<APIResponse<{ group_id: string; files: SharedFile[] }>> {
    try {
      const data = await invoke<any>('api_get_group_files', { groupId });
      return { success: true, data };
    } catch (error) {
      return { success: false, error: error as string };
    }
  }

  // Get public key bundles for multiple users
  async getPublicKeyBundles(userIds: string[]): Promise<APIResponse<{ public_key_bundles: PublicKeyBundleResponse[] }>> {
    try {
      const data = await invoke<any>('api_get_public_key_bundles', { userIds });
      return { success: true, data };
    } catch (error) {
      return { success: false, error: error as string };
    }
  }

  // Get user's message queue
  async getUserMessages(userId: string): Promise<APIResponse<{
    user_id: string;
    messages: any[];
    count: number;
  }>> {
    try {
      const data = await invoke<any>('api_get_user_messages', { userId });
      return { success: true, data };
    } catch (error) {
      return { success: false, error: error as string };
    }
  }

  // Mark message as processed
  async markMessageProcessed(messageId: string): Promise<APIResponse<{
    message_id: string;
    processed: boolean;
  }>> {
    try {
      const data = await invoke<any>('api_mark_message_processed', { messageId });
      return { success: true, data };
    } catch (error) {
      return { success: false, error: error as string };
    }
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

  // Register a new user - now uses auth API
  async register(username: string, password: string, _keyBundle: any): Promise<{ success: boolean; user?: User; error?: string }> {
    return authApi.register(username, password);
  },

  // Login a user - now uses auth API
  async login(username: string, password: string): Promise<{ success: boolean; user?: User; groups?: Group[]; error?: string }> {
    return authApi.login(username, password);
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
  // Note: This method is deprecated in favor of separate blob upload and metadata sharing
  async shareFile(
    groupId: string,
    file: File,
    encryptedContent: string,
    _wrappedMasterKeys: Record<string, WrappedKey>,
    _encryptionMetadata: any,
    sharedBy: string
  ): Promise<{ success: boolean; file?: SharedFile; error?: string }> {
    // First upload the blob
    const blobResponse = await this.uploadBlob(encryptedContent);
    if (!blobResponse.success || !blobResponse.data) {
      return { success: false, error: blobResponse.error || 'Blob upload failed' };
    }

    // Then share the metadata
    const metadataResponse = await apiClient.shareFileMetadata(groupId, {
      original_name: file.name,
      size: file.size,
      mime_type: file.type || 'application/octet-stream',
      shared_by: sharedBy,
      blob_url: blobResponse.data.blob_url,
      blob_hash: blobResponse.data.blob_hash,
    });

    if (metadataResponse.success && metadataResponse.data) {
      return { success: true, file: metadataResponse.data };
    }

    return { success: false, error: metadataResponse.error };
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
  // Note: This functionality needs to be implemented through the new API proxy commands
  async addWrappedKeysForNewMember(
    _groupId: string,
    _userId: string,
    _wrappedKeys: Record<string, WrappedKey>
  ): Promise<{ success: boolean; error?: string }> {
    // TODO: Implement this through Tauri commands when the Go API endpoint is available
    return { success: false, error: "Not yet implemented through Tauri commands" };
  },

  // Get file content and wrapped key for download
  // Note: This functionality needs to be implemented through the new API proxy commands
  async getFileContent(_fileId: string, _userId: string): Promise<{ success: boolean; content?: FileContentResponse; error?: string }> {
    // TODO: Implement this through Tauri commands when the Go API endpoint is available
    return { success: false, error: "Not yet implemented through Tauri commands" };
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
