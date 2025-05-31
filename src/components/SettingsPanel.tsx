import React, { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { DatabaseFilePicker, DirectoryPicker } from "@/components/FilePathPicker";
import { configManager } from "@/lib/config";
import type { AppConfig, AppPreferences, WindowConfig, ThemeMode } from "@/types/config";

interface SettingsPanelProps {
  config: AppConfig | null;
  onConfigUpdate?: () => void;
}

export function SettingsPanel({ config, onConfigUpdate }: SettingsPanelProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Window settings
  const [windowWidth, setWindowWidth] = useState(1200);
  const [windowHeight, setWindowHeight] = useState(800);
  const [windowResizable, setWindowResizable] = useState(true);

  // Database settings
  const [databasePath, setDatabasePath] = useState("");

  // App preferences
  const [theme, setTheme] = useState<ThemeMode>("System");
  const [defaultView, setDefaultView] = useState("files");
  const [showFileExtensions, setShowFileExtensions] = useState(true);
  const [showHiddenFiles, setShowHiddenFiles] = useState(false);
  const [downloadDirectory, setDownloadDirectory] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(true);
  const [autoSaveConfig, setAutoSaveConfig] = useState(true);
  const [language, setLanguage] = useState("en");
  const [checkUpdatesOnStartup, setCheckUpdatesOnStartup] = useState(true);
  const [minimizeToTray, setMinimizeToTray] = useState(false);

  // Load current settings when config changes
  useEffect(() => {
    if (config) {
      // Window settings
      setWindowWidth(config.window.width);
      setWindowHeight(config.window.height);
      setWindowResizable(config.window.resizable);

      // Database settings
      setDatabasePath(config.database_path);

      // App preferences
      setTheme(config.preferences.theme);
      setDefaultView(config.preferences.default_view);
      setShowFileExtensions(config.preferences.show_file_extensions);
      setShowHiddenFiles(config.preferences.show_hidden_files);
      setDownloadDirectory(config.preferences.download_directory || "");
      setConfirmDelete(config.preferences.confirm_delete);
      setAutoSaveConfig(config.preferences.auto_save_config);
      setLanguage(config.preferences.language);
      setCheckUpdatesOnStartup(config.preferences.check_updates_on_startup);
      setMinimizeToTray(config.preferences.minimize_to_tray);
    }
  }, [config]);

  const clearMessages = () => {
    setError(null);
    setSuccess(null);
  };

  const saveWindowSettings = async () => {
    if (!config) return;

    try {
      setLoading(true);
      clearMessages();

      const newWindowConfig: WindowConfig = {
        ...config.window,
        width: windowWidth,
        height: windowHeight,
        resizable: windowResizable,
      };

      await configManager.updateWindowConfig(newWindowConfig);
      setSuccess("Window settings saved successfully!");
      onConfigUpdate?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save window settings");
    } finally {
      setLoading(false);
    }
  };

  const savePreferences = async () => {
    if (!config) return;

    try {
      setLoading(true);
      clearMessages();

      const newPreferences: AppPreferences = {
        theme,
        default_view: defaultView,
        show_file_extensions: showFileExtensions,
        show_hidden_files: showHiddenFiles,
        download_directory: downloadDirectory || undefined,
        confirm_delete: confirmDelete,
        auto_save_config: autoSaveConfig,
        language,
        check_updates_on_startup: checkUpdatesOnStartup,
        minimize_to_tray: minimizeToTray,
      };

      await configManager.updatePreferences(newPreferences);
      setSuccess("Preferences saved successfully!");
      onConfigUpdate?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save preferences");
    } finally {
      setLoading(false);
    }
  };

  const saveDatabaseSettings = async () => {
    if (!config || !databasePath.trim()) {
      setError("Please select a database file");
      return;
    }

    try {
      setLoading(true);
      clearMessages();

      const updatedConfig: AppConfig = {
        ...config,
        database_path: databasePath,
      };

      await configManager.saveConfig(updatedConfig);
      setSuccess("Database settings saved successfully!");
      onConfigUpdate?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save database settings");
    } finally {
      setLoading(false);
    }
  };

  if (!config) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="text-center text-gray-500">
            No configuration loaded. Please initialize the configuration system first.
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Messages */}
      {error && (
        <div className="p-3 bg-red-100 border border-red-400 text-red-700 rounded">
          {error}
        </div>
      )}
      {success && (
        <div className="p-3 bg-green-100 border border-green-400 text-green-700 rounded">
          {success}
        </div>
      )}

      {/* Window Settings */}
      <Card>
        <CardHeader>
          <CardTitle>Window Settings</CardTitle>
          <CardDescription>
            Configure the application window appearance and behavior
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label htmlFor="window-width">Width (pixels)</Label>
              <Input
                id="window-width"
                type="number"
                value={windowWidth}
                onChange={(e) => setWindowWidth(parseInt(e.target.value) || 1200)}
                min={400}
                max={3840}
              />
            </div>
            <div>
              <Label htmlFor="window-height">Height (pixels)</Label>
              <Input
                id="window-height"
                type="number"
                value={windowHeight}
                onChange={(e) => setWindowHeight(parseInt(e.target.value) || 800)}
                min={300}
                max={2160}
              />
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <Switch
              id="window-resizable"
              checked={windowResizable}
              onCheckedChange={setWindowResizable}
            />
            <Label htmlFor="window-resizable">Allow window resizing</Label>
          </div>
          <Button onClick={saveWindowSettings} disabled={loading}>
            Save Window Settings
          </Button>
        </CardContent>
      </Card>

      {/* Database Settings */}
      <Card>
        <CardHeader>
          <CardTitle>Database Settings</CardTitle>
          <CardDescription>
            Configure the location of the encrypted database file
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <DatabaseFilePicker
            label="Database File"
            value={databasePath}
            onChange={setDatabasePath}
            placeholder="Select database file location..."
          />
          <Button onClick={saveDatabaseSettings} disabled={loading}>
            Save Database Settings
          </Button>
        </CardContent>
      </Card>

      {/* Application Preferences */}
      <Card>
        <CardHeader>
          <CardTitle>Application Preferences</CardTitle>
          <CardDescription>
            Customize the application behavior and appearance
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label htmlFor="theme">Theme</Label>
              <Select value={theme} onValueChange={(value: ThemeMode) => setTheme(value)}>
                <SelectTrigger>
                  <SelectValue placeholder="Select theme" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="Light">Light</SelectItem>
                  <SelectItem value="Dark">Dark</SelectItem>
                  <SelectItem value="System">System</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="default-view">Default View</Label>
              <Select value={defaultView} onValueChange={setDefaultView}>
                <SelectTrigger>
                  <SelectValue placeholder="Select default view" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="files">Files</SelectItem>
                  <SelectItem value="vaults">Vaults</SelectItem>
                  <SelectItem value="settings">Settings</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <DirectoryPicker
            label="Download Directory"
            value={downloadDirectory}
            onChange={setDownloadDirectory}
            placeholder="Select default download directory..."
          />

          <Separator />

          <div className="space-y-3">
            <div className="flex items-center space-x-2">
              <Switch
                id="show-extensions"
                checked={showFileExtensions}
                onCheckedChange={setShowFileExtensions}
              />
              <Label htmlFor="show-extensions">Show file extensions</Label>
            </div>
            <div className="flex items-center space-x-2">
              <Switch
                id="show-hidden"
                checked={showHiddenFiles}
                onCheckedChange={setShowHiddenFiles}
              />
              <Label htmlFor="show-hidden">Show hidden files</Label>
            </div>
            <div className="flex items-center space-x-2">
              <Switch
                id="confirm-delete"
                checked={confirmDelete}
                onCheckedChange={setConfirmDelete}
              />
              <Label htmlFor="confirm-delete">Confirm before deleting files</Label>
            </div>
            <div className="flex items-center space-x-2">
              <Switch
                id="auto-save"
                checked={autoSaveConfig}
                onCheckedChange={setAutoSaveConfig}
              />
              <Label htmlFor="auto-save">Auto-save configuration changes</Label>
            </div>
            <div className="flex items-center space-x-2">
              <Switch
                id="check-updates"
                checked={checkUpdatesOnStartup}
                onCheckedChange={setCheckUpdatesOnStartup}
              />
              <Label htmlFor="check-updates">Check for updates on startup</Label>
            </div>
            <div className="flex items-center space-x-2">
              <Switch
                id="minimize-tray"
                checked={minimizeToTray}
                onCheckedChange={setMinimizeToTray}
              />
              <Label htmlFor="minimize-tray">Minimize to system tray</Label>
            </div>
          </div>

          <Button onClick={savePreferences} disabled={loading}>
            Save Preferences
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
