/**
 * TypeScript types for application configuration
 * These types mirror the Rust structs for type safety
 */

export type ThemeMode = "Light" | "Dark" | "System";

export interface WindowConfig {
  width: number;
  height: number;
  x?: number;
  y?: number;
  maximized: boolean;
  fullscreen: boolean;
  resizable: boolean;
  min_width?: number;
  min_height?: number;
}

export interface VaultConfig {
  id: string;
  name: string;
  path: string;
  file_name: string;
  is_active: boolean;
  last_accessed?: string;
  auto_unlock: boolean;
}

export interface AppPreferences {
  theme: ThemeMode;
  default_view: string;
  show_file_extensions: boolean;
  show_hidden_files: boolean;
  download_directory?: string;
  confirm_delete: boolean;
  auto_save_config: boolean;
  language: string;
  check_updates_on_startup: boolean;
  minimize_to_tray: boolean;
}

export interface AppConfig {
  version: string;
  window: WindowConfig;
  vaults: VaultConfig[];
  database_path: string;
  preferences: AppPreferences;
  last_modified?: string;
}

// Default configurations for creating new instances
export const defaultWindowConfig: WindowConfig = {
  width: 1200,
  height: 800,
  x: undefined,
  y: undefined,
  maximized: false,
  fullscreen: false,
  resizable: true,
  min_width: 800,
  min_height: 600,
};

export const defaultAppPreferences: AppPreferences = {
  theme: "System",
  default_view: "files",
  show_file_extensions: true,
  show_hidden_files: false,
  download_directory: undefined,
  confirm_delete: true,
  auto_save_config: true,
  language: "en",
  check_updates_on_startup: true,
  minimize_to_tray: false,
};

export const defaultAppConfig: AppConfig = {
  version: "1.0.0",
  window: defaultWindowConfig,
  vaults: [],
  database_path: "~/Library/Application Support/myfilestorage/secure_storage.db",
  preferences: defaultAppPreferences,
  last_modified: undefined,
};

// Helper functions for working with configurations
export function createVaultConfig(
  name: string,
  path: string,
  fileName: string
): Omit<VaultConfig, "id"> {
  return {
    name,
    path,
    file_name: fileName,
    is_active: false,
    last_accessed: undefined,
    auto_unlock: false,
  };
}

export function isValidTheme(theme: string): theme is ThemeMode {
  return ["Light", "Dark", "System"].includes(theme);
}

export function validateWindowConfig(config: Partial<WindowConfig>): string[] {
  const errors: string[] = [];

  if (config.width !== undefined && config.width < 400) {
    errors.push("Window width must be at least 400 pixels");
  }

  if (config.height !== undefined && config.height < 300) {
    errors.push("Window height must be at least 300 pixels");
  }

  if (config.min_width !== undefined && config.min_width < 400) {
    errors.push("Minimum window width must be at least 400 pixels");
  }

  if (config.min_height !== undefined && config.min_height < 300) {
    errors.push("Minimum window height must be at least 300 pixels");
  }

  return errors;
}

export function validateVaultConfig(config: Partial<VaultConfig>): string[] {
  const errors: string[] = [];

  if (config.name !== undefined && config.name.trim().length === 0) {
    errors.push("Vault name cannot be empty");
  }

  if (config.path !== undefined && config.path.trim().length === 0) {
    errors.push("Vault path cannot be empty");
  }

  if (config.file_name !== undefined && config.file_name.trim().length === 0) {
    errors.push("Vault file name cannot be empty");
  }

  return errors;
}

export function validateAppConfig(config: Partial<AppConfig>): string[] {
  const errors: string[] = [];

  if (config.database_path !== undefined && config.database_path.trim().length === 0) {
    errors.push("Database path cannot be empty");
  }

  if (config.window) {
    errors.push(...validateWindowConfig(config.window));
  }

  if (config.vaults) {
    config.vaults.forEach((vault, index) => {
      const vaultErrors = validateVaultConfig(vault);
      vaultErrors.forEach(error => {
        errors.push(`Vault ${index + 1}: ${error}`);
      });
    });

    // Check that only one vault is active
    const activeVaults = config.vaults.filter(v => v.is_active);
    if (activeVaults.length > 1) {
      errors.push("Only one vault can be active at a time");
    }
  }

  return errors;
}

// Utility type for partial updates
export type ConfigUpdate<T> = Partial<T> & {
  last_modified?: string;
};

// Type guards
export function isWindowConfig(obj: any): obj is WindowConfig {
  return (
    typeof obj === "object" &&
    typeof obj.width === "number" &&
    typeof obj.height === "number" &&
    typeof obj.maximized === "boolean" &&
    typeof obj.fullscreen === "boolean" &&
    typeof obj.resizable === "boolean"
  );
}

export function isVaultConfig(obj: any): obj is VaultConfig {
  return (
    typeof obj === "object" &&
    typeof obj.id === "string" &&
    typeof obj.name === "string" &&
    typeof obj.path === "string" &&
    typeof obj.file_name === "string" &&
    typeof obj.is_active === "boolean" &&
    typeof obj.auto_unlock === "boolean"
  );
}

export function isAppConfig(obj: any): obj is AppConfig {
  return (
    typeof obj === "object" &&
    typeof obj.version === "string" &&
    isWindowConfig(obj.window) &&
    Array.isArray(obj.vaults) &&
    obj.vaults.every(isVaultConfig) &&
    typeof obj.database_path === "string" &&
    typeof obj.preferences === "object"
  );
}
