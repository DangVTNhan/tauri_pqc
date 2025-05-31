import type {
  AppConfig,
  AppPreferences,
  ConfigUpdate,
  VaultConfig,
  WindowConfig,
} from "@/types/config";
import { invoke } from "@tauri-apps/api/core";
import React from "react";

/**
 * Configuration management utilities for the frontend
 */

export class ConfigManager {
  private static instance: ConfigManager;
  private config: AppConfig | null = null;
  private listeners: Set<(config: AppConfig) => void> = new Set();

  private constructor() {}

  public static getInstance(): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instance = new ConfigManager();
    }
    return ConfigManager.instance;
  }

  /**
   * Load configuration from the backend
   */
  public async loadConfig(): Promise<AppConfig> {
    try {
      const config = await invoke<AppConfig>("load_config");
      this.config = config;
      this.notifyListeners();
      return config;
    } catch (error) {
      console.error("Failed to load configuration:", error);
      throw new Error(`Failed to load configuration: ${error}`);
    }
  }

  /**
   * Save configuration to the backend
   */
  public async saveConfig(config: AppConfig): Promise<void> {
    try {
      await invoke<string>("save_config", { config });
      this.config = config;
      this.notifyListeners();
    } catch (error) {
      console.error("Failed to save configuration:", error);
      throw new Error(`Failed to save configuration: ${error}`);
    }
  }

  /**
   * Get the current configuration (cached)
   */
  public getConfig(): AppConfig | null {
    return this.config;
  }

  /**
   * Initialize the configuration system
   */
  public async initializeConfig(): Promise<AppConfig> {
    try {
      const config = await invoke<AppConfig>("init_config_system");
      this.config = config;
      this.notifyListeners();
      return config;
    } catch (error) {
      console.error("Failed to initialize configuration:", error);
      throw new Error(`Failed to initialize configuration: ${error}`);
    }
  }

  /**
   * Create a new vault with encryption
   */
  public async createVault(request: {
    name: string;
    path: string;
    password: string;
  }): Promise<void> {
    try {
      const response = await invoke<{
        vault_config: VaultConfig;
        message: string;
      }>("create_vault", {
        request: {
          name: request.name,
          path: request.path,
          password: request.password,
        },
      });
      console.log("Vault created successfully:", response.message);
      await this.loadConfig(); // Reload to get the updated configuration
    } catch (error) {
      console.error("Failed to create vault:", error);
      throw new Error(`Failed to create vault: ${error}`);
    }
  }

  /**
   * Add a vault to the configuration
   */
  public async addVault(vault: Omit<VaultConfig, "id">): Promise<void> {
    try {
      // Create a vault config with a temporary ID (backend will generate the real one)
      const vaultWithId: VaultConfig = {
        ...vault,
        id: crypto.randomUUID(),
      };

      await invoke<string>("add_vault", { vault: vaultWithId });
      await this.loadConfig(); // Reload to get the updated configuration
    } catch (error) {
      console.error("Failed to add vault:", error);
      throw new Error(`Failed to add vault: ${error}`);
    }
  }

  /**
   * Remove a vault from the configuration
   */
  public async removeVault(vaultId: string): Promise<void> {
    try {
      await invoke<string>("remove_vault", { vaultId });
      await this.loadConfig(); // Reload to get the updated configuration
    } catch (error) {
      console.error("Failed to remove vault:", error);
      throw new Error(`Failed to remove vault: ${error}`);
    }
  }

  /**
   * Set the active vault
   */
  public async setActiveVault(vaultId: string): Promise<void> {
    try {
      await invoke<string>("set_active_vault", { vaultId });
      await this.loadConfig(); // Reload to get the updated configuration
    } catch (error) {
      console.error("Failed to set active vault:", error);
      throw new Error(`Failed to set active vault: ${error}`);
    }
  }

  /**
   * Get the currently active vault
   */
  public async getActiveVault(): Promise<VaultConfig | null> {
    try {
      const vault = await invoke<VaultConfig | null>("get_active_vault");
      return vault;
    } catch (error) {
      console.error("Failed to get active vault:", error);
      throw new Error(`Failed to get active vault: ${error}`);
    }
  }

  /**
   * Verify vault password
   */
  public async verifyVaultPassword(
    vaultPath: string,
    password: string
  ): Promise<boolean> {
    try {
      return await invoke<boolean>("verify_vault_password", {
        vault_path: vaultPath,
        password,
      });
    } catch (error) {
      console.error("Failed to verify vault password:", error);
      throw new Error(`Failed to verify vault password: ${error}`);
    }
  }

  /**
   * Check if a directory is a valid vault
   */
  public async isValidVault(vaultPath: string): Promise<boolean> {
    try {
      return await invoke<boolean>("is_valid_vault", { vault_path: vaultPath });
    } catch (error) {
      console.error("Failed to check vault validity:", error);
      throw new Error(`Failed to check vault validity: ${error}`);
    }
  }

  /**
   * Update window configuration
   */
  public async updateWindowConfig(windowConfig: WindowConfig): Promise<void> {
    try {
      await invoke<string>("update_window_config", { windowConfig });
      if (this.config) {
        this.config.window = windowConfig;
        this.notifyListeners();
      }
    } catch (error) {
      console.error("Failed to update window configuration:", error);
      throw new Error(`Failed to update window configuration: ${error}`);
    }
  }

  /**
   * Update application preferences
   */
  public async updatePreferences(preferences: AppPreferences): Promise<void> {
    try {
      await invoke<string>("update_preferences", { preferences });
      if (this.config) {
        this.config.preferences = preferences;
        this.notifyListeners();
      }
    } catch (error) {
      console.error("Failed to update preferences:", error);
      throw new Error(`Failed to update preferences: ${error}`);
    }
  }

  /**
   * Get application data directory path
   */
  public async getAppDataDir(): Promise<string> {
    try {
      return await invoke<string>("get_app_data_dir");
    } catch (error) {
      console.error("Failed to get app data directory:", error);
      throw new Error(`Failed to get app data directory: ${error}`);
    }
  }

  /**
   * Get configuration file path
   */
  public async getConfigPath(): Promise<string> {
    try {
      return await invoke<string>("get_config_path");
    } catch (error) {
      console.error("Failed to get config path:", error);
      throw new Error(`Failed to get config path: ${error}`);
    }
  }

  /**
   * Create a backup of the current configuration
   */
  public async backupConfig(): Promise<string> {
    try {
      return await invoke<string>("backup_config");
    } catch (error) {
      console.error("Failed to backup configuration:", error);
      throw new Error(`Failed to backup configuration: ${error}`);
    }
  }

  /**
   * Restore configuration from backup
   */
  public async restoreFromBackup(): Promise<void> {
    try {
      await invoke<string>("restore_config_from_backup");
      await this.loadConfig(); // Reload to get the restored configuration
    } catch (error) {
      console.error("Failed to restore configuration:", error);
      throw new Error(`Failed to restore configuration: ${error}`);
    }
  }

  /**
   * Reset configuration to defaults
   */
  public async resetToDefaults(): Promise<void> {
    try {
      await invoke<string>("reset_config_to_defaults");
      await this.loadConfig(); // Reload to get the default configuration
    } catch (error) {
      console.error("Failed to reset configuration:", error);
      throw new Error(`Failed to reset configuration: ${error}`);
    }
  }

  /**
   * Validate the current configuration
   */
  public async validateConfig(): Promise<void> {
    try {
      await invoke<string>("validate_config");
    } catch (error) {
      console.error("Configuration validation failed:", error);
      throw new Error(`Configuration validation failed: ${error}`);
    }
  }

  /**
   * Subscribe to configuration changes
   */
  public subscribe(listener: (config: AppConfig) => void): () => void {
    this.listeners.add(listener);

    // Return unsubscribe function
    return () => {
      this.listeners.delete(listener);
    };
  }

  /**
   * Notify all listeners of configuration changes
   */
  private notifyListeners(): void {
    if (this.config) {
      this.listeners.forEach((listener) => listener(this.config!));
    }
  }
}

// Export a singleton instance
export const configManager = ConfigManager.getInstance();

// Utility functions for common operations
export async function initializeApp(): Promise<AppConfig> {
  return await configManager.initializeConfig();
}

export async function getCurrentConfig(): Promise<AppConfig> {
  const cached = configManager.getConfig();
  if (cached) {
    return cached;
  }
  return await configManager.loadConfig();
}

export async function updateConfig(updates: ConfigUpdate<AppConfig>): Promise<void> {
  const current = await getCurrentConfig();
  const updated: AppConfig = {
    ...current,
    ...updates,
    last_modified: new Date().toISOString(),
  };
  await configManager.saveConfig(updated);
}

// React hook for configuration (if using React)
export function useConfig() {
  const [config, setConfig] = React.useState<AppConfig | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    const loadConfig = async () => {
      try {
        setLoading(true);
        const loadedConfig = await configManager.loadConfig();
        setConfig(loadedConfig);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load configuration");
      } finally {
        setLoading(false);
      }
    };

    loadConfig();

    // Subscribe to configuration changes
    const unsubscribe = configManager.subscribe(setConfig);

    return unsubscribe;
  }, []);

  return { config, loading, error, configManager };
}
