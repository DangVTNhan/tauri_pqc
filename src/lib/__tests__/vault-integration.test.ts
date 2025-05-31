/**
 * Integration tests for vault operations
 * These tests verify the frontend-backend integration for vault management
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { configManager } from '../config';

// Mock Tauri invoke function
const mockInvoke = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({
  invoke: mockInvoke,
}));

describe('Vault Integration Tests', () => {
  beforeEach(() => {
    mockInvoke.mockClear();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('createVault', () => {
    it('should successfully create a vault with valid parameters', async () => {
      const mockResponse = {
        vault_config: {
          id: 'test-vault-id',
          name: 'Test Vault',
          path: '/tmp/test',
          file_name: 'test_vault',
          is_active: false,
          auto_unlock: false,
        },
        message: 'Vault "Test Vault" created successfully',
      };

      mockInvoke
        .mockResolvedValueOnce(mockResponse) // create_vault call
        .mockResolvedValueOnce({ vaults: [mockResponse.vault_config] }); // loadConfig call

      const request = {
        name: 'Test Vault',
        path: '/tmp/test',
        password: 'secure_password_123',
      };

      await configManager.createVault(request);

      expect(mockInvoke).toHaveBeenCalledWith('create_vault', {
        request: {
          name: 'Test Vault',
          path: '/tmp/test',
          password: 'secure_password_123',
        },
      });

      expect(mockInvoke).toHaveBeenCalledWith('load_config');
      expect(mockInvoke).toHaveBeenCalledTimes(2);
    });

    it('should handle vault creation errors', async () => {
      const errorMessage = 'Vault directory already exists';
      mockInvoke.mockRejectedValueOnce(new Error(errorMessage));

      const request = {
        name: 'Duplicate Vault',
        path: '/tmp/test',
        password: 'secure_password_123',
      };

      await expect(configManager.createVault(request)).rejects.toThrow(
        `Failed to create vault: Error: ${errorMessage}`
      );

      expect(mockInvoke).toHaveBeenCalledWith('create_vault', {
        request: {
          name: 'Duplicate Vault',
          path: '/tmp/test',
          password: 'secure_password_123',
        },
      });

      expect(mockInvoke).toHaveBeenCalledTimes(1);
    });

    it('should handle network/communication errors', async () => {
      mockInvoke.mockRejectedValueOnce(new Error('Connection failed'));

      const request = {
        name: 'Network Test Vault',
        path: '/tmp/test',
        password: 'secure_password_123',
      };

      await expect(configManager.createVault(request)).rejects.toThrow(
        'Failed to create vault: Error: Connection failed'
      );
    });
  });

  describe('verifyVaultPassword', () => {
    it('should verify correct password', async () => {
      mockInvoke.mockResolvedValueOnce(true);

      const result = await configManager.verifyVaultPassword(
        '/tmp/test_vault',
        'correct_password'
      );

      expect(result).toBe(true);
      expect(mockInvoke).toHaveBeenCalledWith('verify_vault_password', {
        vault_path: '/tmp/test_vault',
        password: 'correct_password',
      });
    });

    it('should reject incorrect password', async () => {
      mockInvoke.mockResolvedValueOnce(false);

      const result = await configManager.verifyVaultPassword(
        '/tmp/test_vault',
        'wrong_password'
      );

      expect(result).toBe(false);
      expect(mockInvoke).toHaveBeenCalledWith('verify_vault_password', {
        vault_path: '/tmp/test_vault',
        password: 'wrong_password',
      });
    });

    it('should handle vault not found errors', async () => {
      mockInvoke.mockRejectedValueOnce(new Error('Master key file not found'));

      await expect(
        configManager.verifyVaultPassword('/nonexistent/vault', 'any_password')
      ).rejects.toThrow('Failed to verify vault password');
    });
  });

  describe('isValidVault', () => {
    it('should return true for valid vault directory', async () => {
      mockInvoke.mockResolvedValueOnce(true);

      const result = await configManager.isValidVault('/tmp/valid_vault');

      expect(result).toBe(true);
      expect(mockInvoke).toHaveBeenCalledWith('is_valid_vault', {
        vault_path: '/tmp/valid_vault',
      });
    });

    it('should return false for invalid vault directory', async () => {
      mockInvoke.mockResolvedValueOnce(false);

      const result = await configManager.isValidVault('/tmp/invalid_vault');

      expect(result).toBe(false);
      expect(mockInvoke).toHaveBeenCalledWith('is_valid_vault', {
        vault_path: '/tmp/invalid_vault',
      });
    });

    it('should handle file system errors', async () => {
      mockInvoke.mockRejectedValueOnce(new Error('Permission denied'));

      await expect(
        configManager.isValidVault('/restricted/vault')
      ).rejects.toThrow('Failed to check vault validity');
    });
  });

  describe('Vault Creation Workflow', () => {
    it('should complete full vault creation workflow', async () => {
      const vaultConfig = {
        id: 'workflow-test-id',
        name: 'Workflow Test Vault',
        path: '/tmp/workflow',
        file_name: 'workflow_test_vault',
        is_active: false,
        auto_unlock: false,
      };

      const createResponse = {
        vault_config: vaultConfig,
        message: 'Vault "Workflow Test Vault" created successfully',
      };

      // Mock the sequence of calls
      mockInvoke
        .mockResolvedValueOnce(createResponse) // create_vault
        .mockResolvedValueOnce({ vaults: [vaultConfig] }) // loadConfig after creation
        .mockResolvedValueOnce(true) // isValidVault check
        .mockResolvedValueOnce(true); // verifyVaultPassword check

      const request = {
        name: 'Workflow Test Vault',
        path: '/tmp/workflow',
        password: 'workflow_password_123',
      };

      // Step 1: Create vault
      await configManager.createVault(request);

      // Step 2: Verify vault is valid
      const isValid = await configManager.isValidVault('/tmp/workflow/workflow_test_vault');
      expect(isValid).toBe(true);

      // Step 3: Verify password works
      const passwordValid = await configManager.verifyVaultPassword(
        '/tmp/workflow/workflow_test_vault',
        'workflow_password_123'
      );
      expect(passwordValid).toBe(true);

      // Verify all calls were made
      expect(mockInvoke).toHaveBeenCalledTimes(4);
    });
  });

  describe('Error Handling', () => {
    it('should handle malformed responses', async () => {
      mockInvoke.mockResolvedValueOnce(null);

      const request = {
        name: 'Malformed Test',
        path: '/tmp/test',
        password: 'test_password',
      };

      // This should not throw, but the response might be unexpected
      await expect(configManager.createVault(request)).resolves.not.toThrow();
    });

    it('should handle timeout errors', async () => {
      mockInvoke.mockRejectedValueOnce(new Error('Request timeout'));

      const request = {
        name: 'Timeout Test',
        path: '/tmp/test',
        password: 'test_password',
      };

      await expect(configManager.createVault(request)).rejects.toThrow(
        'Failed to create vault: Error: Request timeout'
      );
    });

    it('should handle backend unavailable errors', async () => {
      mockInvoke.mockRejectedValueOnce(new Error('Backend not available'));

      await expect(
        configManager.verifyVaultPassword('/tmp/vault', 'password')
      ).rejects.toThrow('Failed to verify vault password');
    });
  });

  describe('Parameter Validation', () => {
    it('should pass through all required parameters for vault creation', async () => {
      const mockResponse = {
        vault_config: {
          id: 'param-test-id',
          name: 'Parameter Test',
          path: '/custom/path',
          file_name: 'parameter_test',
          is_active: false,
          auto_unlock: false,
        },
        message: 'Success',
      };

      mockInvoke
        .mockResolvedValueOnce(mockResponse)
        .mockResolvedValueOnce({ vaults: [] });

      const request = {
        name: 'Parameter Test',
        path: '/custom/path',
        password: 'parameter_password_456',
      };

      await configManager.createVault(request);

      expect(mockInvoke).toHaveBeenCalledWith('create_vault', {
        request: {
          name: 'Parameter Test',
          path: '/custom/path',
          password: 'parameter_password_456',
        },
      });
    });

    it('should handle special characters in vault names', async () => {
      const mockResponse = {
        vault_config: {
          id: 'special-char-id',
          name: 'Special!@#$%^&*()Vault',
          path: '/tmp/special',
          file_name: 'special_vault',
          is_active: false,
          auto_unlock: false,
        },
        message: 'Success',
      };

      mockInvoke
        .mockResolvedValueOnce(mockResponse)
        .mockResolvedValueOnce({ vaults: [] });

      const request = {
        name: 'Special!@#$%^&*()Vault',
        path: '/tmp/special',
        password: 'special_password_789',
      };

      await configManager.createVault(request);

      expect(mockInvoke).toHaveBeenCalledWith('create_vault', {
        request: {
          name: 'Special!@#$%^&*()Vault',
          path: '/tmp/special',
          password: 'special_password_789',
        },
      });
    });

    it('should handle unicode characters in paths', async () => {
      const mockResponse = {
        vault_config: {
          id: 'unicode-test-id',
          name: 'Unicode Test',
          path: '/tmp/测试/vault',
          file_name: 'unicode_test',
          is_active: false,
          auto_unlock: false,
        },
        message: 'Success',
      };

      mockInvoke
        .mockResolvedValueOnce(mockResponse)
        .mockResolvedValueOnce({ vaults: [] });

      const request = {
        name: 'Unicode Test',
        path: '/tmp/测试/vault',
        password: 'unicode_password_123',
      };

      await configManager.createVault(request);

      expect(mockInvoke).toHaveBeenCalledWith('create_vault', {
        request: {
          name: 'Unicode Test',
          path: '/tmp/测试/vault',
          password: 'unicode_password_123',
        },
      });
    });
  });
});
