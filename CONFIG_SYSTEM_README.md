# Configuration System for Tauri Application

This document describes the comprehensive configuration system implemented for the Tauri + React + TypeScript application with Shadcn UI and Tailwind CSS v4.

## Overview

The configuration system provides a robust foundation for managing application settings, window preferences, vault configurations, and user preferences. It includes automatic configuration file creation, validation, backup/restore functionality, and seamless integration between the Rust backend and TypeScript frontend.

## Architecture

### Backend (Rust)

#### Core Components

1. **Configuration Models** (`src-tauri/src/models/config.rs`)
   - `AppConfig`: Main configuration structure
   - `WindowConfig`: Window dimensions and positioning
   - `VaultConfig`: Individual vault configurations
   - `AppPreferences`: User preferences and settings
   - `ThemeMode`: Theme selection (Light, Dark, System)

2. **Configuration Manager** (`src-tauri/src/config/mod.rs`)
   - `ConfigManager`: Core configuration management logic
   - Automatic file creation and validation
   - Configuration migration support
   - Backup and restore functionality

3. **Tauri Commands** (`src-tauri/src/config/commands.rs`)
   - Complete set of commands for configuration operations
   - State management with thread-safe access
   - Error handling and validation

#### Key Features

- **Automatic Initialization**: Creates default configuration on first run
- **File System Integration**: Uses Tauri's app data directory
- **Validation**: Comprehensive configuration validation
- **Migration Support**: Version-based configuration migration
- **Backup/Restore**: Built-in backup and restore functionality
- **Thread Safety**: Mutex-protected state management

### Frontend (TypeScript)

#### Core Components

1. **Type Definitions** (`src/types/config.ts`)
   - TypeScript interfaces mirroring Rust structs
   - Type guards and validation functions
   - Default configuration objects
   - Utility types for partial updates

2. **Configuration Manager** (`src/lib/config.ts`)
   - Singleton pattern for configuration management
   - React hooks for configuration state
   - Automatic synchronization with backend
   - Event-driven updates

3. **Demo Component** (`src/components/ConfigDemo.tsx`)
   - Interactive demonstration of configuration features
   - Vault management interface
   - Real-time configuration display

## Configuration Structure

### AppConfig
```typescript
interface AppConfig {
  version: string;                    // Configuration version for migration
  window: WindowConfig;               // Window settings
  vaults: VaultConfig[];             // Array of vault configurations
  database_path: string;             // Path to encrypted SQLite database
  preferences: AppPreferences;       // User preferences
  last_modified?: string;            // Last modification timestamp
}
```

### WindowConfig
```typescript
interface WindowConfig {
  width: number;                     // Window width in pixels
  height: number;                    // Window height in pixels
  x?: number;                        // Window x position (optional)
  y?: number;                        // Window y position (optional)
  maximized: boolean;                // Whether window is maximized
  fullscreen: boolean;               // Whether window is fullscreen
  resizable: boolean;                // Whether window is resizable
  min_width?: number;                // Minimum window width
  min_height?: number;               // Minimum window height
}
```

### VaultConfig
```typescript
interface VaultConfig {
  id: string;                        // Unique vault identifier
  name: string;                      // Display name
  path: string;                      // File path to vault directory
  file_name: string;                 // Vault file name
  is_active: boolean;                // Whether vault is currently active
  last_accessed?: string;            // Last access timestamp
  auto_unlock: boolean;              // Auto-unlock on startup
}
```

### AppPreferences
```typescript
interface AppPreferences {
  theme: ThemeMode;                  // Theme selection
  default_view: string;              // Default view on startup
  show_file_extensions: boolean;     // Show file extensions
  show_hidden_files: boolean;        // Show hidden files
  download_directory?: string;       // Default download directory
  confirm_delete: boolean;           // Confirm before deleting
  auto_save_config: boolean;         // Auto-save configuration changes
  language: string;                  // Language/locale setting
  check_updates_on_startup: boolean; // Check for updates on startup
  minimize_to_tray: boolean;         // Minimize to system tray
}
```

## Available Commands

### Configuration Management
- `load_config()`: Load current configuration
- `save_config(config)`: Save configuration
- `init_config_system()`: Initialize configuration system
- `validate_config()`: Validate current configuration
- `reset_config_to_defaults()`: Reset to default configuration

### Vault Management
- `add_vault(vault)`: Add new vault configuration
- `remove_vault(vault_id)`: Remove vault by ID
- `set_active_vault(vault_id)`: Set active vault
- `get_active_vault()`: Get currently active vault

### Preferences
- `update_window_config(window_config)`: Update window settings
- `update_preferences(preferences)`: Update user preferences

### Utility
- `get_app_data_dir()`: Get application data directory path
- `get_config_path()`: Get configuration file path
- `backup_config()`: Create configuration backup
- `restore_config_from_backup()`: Restore from backup
- `ensure_directories()`: Ensure required directories exist

## Usage Examples

### Frontend Configuration Management

```typescript
import { configManager } from "@/lib/config";

// Initialize configuration system
const config = await configManager.initializeConfig();

// Add a new vault
await configManager.addVault({
  name: "My Secure Vault",
  path: "/path/to/vault",
  file_name: "vault.db",
  is_active: false,
  auto_unlock: false,
});

// Update preferences
await configManager.updatePreferences({
  ...config.preferences,
  theme: "Dark",
  auto_save_config: true,
});

// Subscribe to configuration changes
const unsubscribe = configManager.subscribe((newConfig) => {
  console.log("Configuration updated:", newConfig);
});
```

### React Hook Usage

```typescript
import { useConfig } from "@/lib/config";

function MyComponent() {
  const { config, loading, error, configManager } = useConfig();

  if (loading) return <div>Loading configuration...</div>;
  if (error) return <div>Error: {error}</div>;

  return (
    <div>
      <h1>Current Theme: {config?.preferences.theme}</h1>
      <button onClick={() => configManager.resetToDefaults()}>
        Reset to Defaults
      </button>
    </div>
  );
}
```

## File Locations

- **Configuration File**: `~/Library/Application Support/myfilestorage/settings.json`
- **Backup File**: `~/Library/Application Support/myfilestorage/settings.json.backup`
- **Database File**: `~/Library/Application Support/myfilestorage/secure_storage.db`
- **App Data Directory**: `~/Library/Application Support/myfilestorage/`

Note: The `~` represents the user's home directory (e.g., `/Users/username/`)

## Error Handling

The system includes comprehensive error handling:
- Configuration validation on load and save
- Automatic backup creation before risky operations
- Graceful fallback to defaults on corruption
- Detailed error messages for debugging

## Migration Support

The configuration system supports version-based migration:
- Automatic detection of configuration version changes
- Backup creation before migration
- Extensible migration framework for future updates

## Integration with Existing Systems

The configuration system is designed to integrate seamlessly with:
- Existing Vault system (when implemented)
- Storage system with encryption support
- Window management and theming
- File system operations

## Testing the System

The application includes a comprehensive demo component that allows you to:
1. Initialize the configuration system
2. View current configuration settings
3. Add and manage vault configurations
4. Test backup and restore functionality
5. Explore all available configuration options

## Future Enhancements

Potential future improvements include:
- Configuration synchronization across devices
- Advanced validation rules
- Configuration templates
- Import/export functionality
- Real-time configuration watching
