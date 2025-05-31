import { DirectoryPicker } from "@/components/FilePathPicker";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { configManager } from "@/lib/config";
import type { VaultConfig } from "@/types/config";
import { useState } from "react";

interface VaultManagerProps {
  vaults: VaultConfig[];
  onVaultUpdate: () => void;
}

export function VaultManager({ vaults, onVaultUpdate }: VaultManagerProps) {
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Create new vault state
  const [newVaultName, setNewVaultName] = useState("");
  const [newVaultPath, setNewVaultPath] = useState("");
  const [newVaultPassword, setNewVaultPassword] = useState("");

  // Success message state
  const [successMessage, setSuccessMessage] = useState("");

  const clearMessages = () => {
    setError(null);
    setSuccessMessage("");
  };

  const createNewVault = async () => {
    if (!newVaultName.trim()) {
      setError("Please enter a vault name");
      return;
    }

    if (!newVaultPath.trim()) {
      setError("Please select a vault directory");
      return;
    }

    if (!newVaultPassword.trim()) {
      setError("Please enter a vault password");
      return;
    }

    if (newVaultPassword.length < 8) {
      setError("Password must be at least 8 characters long");
      return;
    }

    try {
      setLoading(true);
      clearMessages();

      // Create vault directory name from vault name
      const sanitizedName = newVaultName.toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9_]/g, '');

      // Call Tauri command to create vault directory with encryption
      await configManager.createVault({
        name: newVaultName,
        path: newVaultPath,
        password: newVaultPassword,
      });

      // Show success message
      setSuccessMessage(`Vault "${newVaultName}" created successfully!`);

      // Clear form
      setNewVaultName("");
      setNewVaultPath("");
      setNewVaultPassword("");

      onVaultUpdate();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create vault");
    } finally {
      setLoading(false);
    }
  };



  const setActiveVault = async (vaultId: string) => {
    try {
      setLoading(true);
      clearMessages();
      await configManager.setActiveVault(vaultId);
      onVaultUpdate();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to set active vault");
    } finally {
      setLoading(false);
    }
  };

  const removeVault = async (vaultId: string) => {
    if (!confirm("Are you sure you want to remove this vault configuration? This will not delete the vault file.")) {
      return;
    }

    try {
      setLoading(true);
      clearMessages();
      await configManager.removeVault(vaultId);
      onVaultUpdate();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove vault");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Error Display */}
      {error && (
        <div className="p-3 bg-red-100 border border-red-400 text-red-700 rounded">
          {error}
        </div>
      )}

      {/* Success Display */}
      {successMessage && (
        <div className="p-3 bg-green-100 border border-green-400 text-green-700 rounded">
          {successMessage}
        </div>
      )}

      {/* Create New Vault */}
      <Card>
        <CardHeader>
          <CardTitle>Create New Vault</CardTitle>
          <CardDescription>
            Create a new encrypted vault directory with secure file storage
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 gap-4">
            <div>
              <Label htmlFor="new-vault-name">Vault Name</Label>
              <Input
                id="new-vault-name"
                value={newVaultName}
                onChange={(e) => setNewVaultName(e.target.value)}
                placeholder="My Secure Vault"
                disabled={loading}
              />
              <p className="text-xs text-gray-500 mt-1">
                The vault directory will be created as: {newVaultName ? `${newVaultName.toLowerCase().replace(/\s+/g, '_')}` : 'vault_name'}
              </p>
            </div>
            <div>
              <Label htmlFor="new-vault-password">Vault Password</Label>
              <Input
                id="new-vault-password"
                type="password"
                value={newVaultPassword}
                onChange={(e) => setNewVaultPassword(e.target.value)}
                placeholder="Enter a strong password (min 8 characters)"
                disabled={loading}
              />
              <p className="text-xs text-gray-500 mt-1">
                This password will be used to encrypt your vault data. Make sure to remember it!
              </p>
            </div>
            <DirectoryPicker
              label="Parent Directory"
              value={newVaultPath}
              onChange={setNewVaultPath}
              placeholder="Select directory where vault will be created..."
              disabled={loading}
            />
            {newVaultPath && newVaultName && (
              <div className="p-3 bg-blue-50 border border-blue-200 rounded">
                <p className="text-sm text-blue-800">
                  <strong>Vault directory will be created at:</strong><br />
                  {newVaultPath}/{newVaultName.toLowerCase().replace(/\s+/g, '_')}/
                </p>
                <p className="text-xs text-blue-600 mt-1">
                  This directory will contain encrypted files: masterkey.silvertiger and vault_config.silvertiger
                </p>
              </div>
            )}
          </div>
          <Button onClick={createNewVault} className="w-full" disabled={loading}>
            {loading ? "Creating..." : "Create Vault"}
          </Button>
        </CardContent>
      </Card>



      {/* Configured Vaults */}
      {vaults.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Configured Vaults</CardTitle>
            <CardDescription>
              Manage your vault configurations
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {vaults.map((vault: VaultConfig) => (
                <div
                  key={vault.id}
                  className={`p-3 border rounded-lg ${
                    vault.is_active ? "border-blue-500 bg-blue-50" : "border-gray-200"
                  }`}
                >
                  <div className="flex justify-between items-start">
                    <div className="flex-1">
                      <h4 className="font-medium">
                        {vault.name}
                        {vault.is_active && (
                          <span className="ml-2 px-2 py-1 text-xs bg-blue-500 text-white rounded">
                            Active
                          </span>
                        )}
                      </h4>
                      <p className="text-sm text-gray-600">
                        Parent Directory: {vault.path}
                      </p>
                      <p className="text-sm text-gray-600">
                        Vault Directory: {vault.file_name}
                      </p>
                      <p className="text-sm text-gray-500">
                        Full path: {vault.path}/{vault.file_name}/
                      </p>
                      {vault.last_accessed && (
                        <p className="text-sm text-gray-500">
                          Last accessed: {new Date(vault.last_accessed).toLocaleString()}
                        </p>
                      )}
                    </div>
                    <div className="flex gap-2">
                      {!vault.is_active && (
                        <Button
                          size="sm"
                          onClick={() => setActiveVault(vault.id)}
                          disabled={loading}
                        >
                          Set Active
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="destructive"
                        onClick={() => removeVault(vault.id)}
                        disabled={loading}
                      >
                        Remove
                      </Button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
