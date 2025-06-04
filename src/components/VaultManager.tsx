import { DirectoryPicker } from "@/components/FilePathPicker";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PasswordDialog } from "@/components/ui/password-dialog";
import { configManager } from "@/lib/config";
import type { VaultConfig } from "@/types/config";
import { invoke } from '@tauri-apps/api/core';
import {
  CheckCircle,
  Copy,
  ExternalLink,
  Globe,
  Loader2,
  Lock,
  Unlock
} from 'lucide-react';
import { useEffect, useState } from "react";
import { toast } from 'sonner';

// WebDAV-related types
type VaultStatus = 'Locked' | 'Unlocked';

interface VaultMount {
  vault_id: string;
  vault_name: string;
  vault_path: string;
  status: VaultStatus;
  webdav_config: {
    host: string;
    port: number;
    is_running: boolean;
    started_at?: string;
  };
  mount_url?: string;
  last_accessed?: string;
}

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

  // WebDAV state
  const [vaultStatuses, setVaultStatuses] = useState<Record<string, VaultStatus>>({});
  const [vaultMountUrls, setVaultMountUrls] = useState<Record<string, string>>({});
  const [selectedVault, setSelectedVault] = useState<VaultConfig | null>(null);
  const [passwordDialogOpen, setPasswordDialogOpen] = useState(false);
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [passwordError, setPasswordError] = useState<string>('');
  const [operationLoading, setOperationLoading] = useState<Record<string, boolean>>({});

  // Load vault statuses on component mount
  useEffect(() => {
    loadVaultStatuses();
  }, []);

  const clearMessages = () => {
    setError(null);
    setSuccessMessage("");
  };

  const loadVaultStatuses = async () => {
    try {
      const statuses = await invoke<Record<string, VaultStatus>>('get_vault_statuses');
      setVaultStatuses(statuses);
    } catch (error) {
      console.error('Failed to load vault statuses:', error);
    }
  };

  const handleUnlockVault = (vault: VaultConfig) => {
    setSelectedVault(vault);
    setPasswordError('');
    setPasswordDialogOpen(true);
  };

  const handlePasswordSubmit = async (password: string) => {
    if (!selectedVault) return;

    setIsUnlocking(true);
    setPasswordError('');

    console.log("password: " + password);
    console.log("select vault id" + selectedVault.id);

    try {
      const response = await invoke<{
        success: boolean;
        vault_mount?: VaultMount;
        error?: string;
      }>('unlock_vault', {
        request: {
          vault_id: selectedVault.id,
          password: password,
        }
      });

      if (response.success && response.vault_mount) {
        // Store the mount URL
        if (response.vault_mount.mount_url) {
          setVaultMountUrls(prev => ({
            ...prev,
            [selectedVault.id]: response.vault_mount!.mount_url!
          }));

          // Automatically open Finder to show the vault content
          try {
            await invoke('open_url', {
              url: response.vault_mount.mount_url,
              vaultName: selectedVault.name
            });
            toast.success(`Vault "${selectedVault.name}" unlocked and opened in Finder`);
          } catch (openError) {
            console.error('Failed to open Finder:', openError);
            toast.success(`Vault "${selectedVault.name}" unlocked successfully`);
          }
        } else {
          toast.success(`Vault "${selectedVault.name}" unlocked successfully`);
        }

        setPasswordDialogOpen(false);
        await loadVaultStatuses();
      } else {
        setPasswordError(response.error || 'Failed to unlock vault');
      }
    } catch (error) {
      console.error('Failed to unlock vault - Full error object:', error);
      console.error('Error type:', typeof error);
      console.error('Error constructor:', error?.constructor?.name);

      let errorMessage = "An unexpected error occurred";

      if (error instanceof Error) {
        errorMessage = error.message;
        console.error('Error message:', error.message);
        console.error('Error stack:', error.stack);
      } else if (typeof error === 'string') {
        errorMessage = error;
      } else if (error && typeof error === 'object') {
        try {
          errorMessage = JSON.stringify(error, null, 2);
        } catch (jsonError) {
          errorMessage = String(error);
        }
      } else {
        errorMessage = String(error);
      }

      setPasswordError(errorMessage);
    } finally {
      setIsUnlocking(false);
    }
  };



  const handleLockVault = async (vaultId: string) => {
    setOperationLoading(prev => ({ ...prev, [vaultId]: true }));

    try {
      const response = await invoke<{
        success: boolean;
        error?: string;
      }>('lock_vault', { vaultId });

      if (response.success) {
        // Clear the mount URL
        setVaultMountUrls(prev => {
          const updated = { ...prev };
          delete updated[vaultId];
          return updated;
        });

        toast.success('Vault locked successfully');
        await loadVaultStatuses();
      } else {
        toast.error(response.error || 'Failed to lock vault');
      }
    } catch (error) {
      console.error('Failed to lock vault:', error);
      toast.error('An unexpected error occurred');
    } finally {
      setOperationLoading(prev => ({ ...prev, [vaultId]: false }));
    }
  };

  const copyMountUrl = async (mountUrl: string) => {
    try {
      await navigator.clipboard.writeText(mountUrl);
      toast.success('Mount URL copied to clipboard');
    } catch (error) {
      console.error('Failed to copy URL:', error);
      toast.error('Failed to copy URL');
    }
  };

  const openInFinder = async (mountUrl: string, vaultName?: string) => {
    try {
      await invoke('open_url', {
        url: mountUrl,
        vaultName: vaultName
      });
    } catch (error) {
      console.error('Failed to open in Finder:', error);
      toast.error('Failed to open in Finder');
    }
  };

  const getStatusBadge = (status: VaultStatus) => {
    switch (status) {
      case 'Locked':
        return <Badge variant="secondary" className="gap-1"><Lock className="h-3 w-3" />Locked</Badge>;
      case 'Unlocked':
        return <Badge variant="default" className="gap-1"><Globe className="h-3 w-3" />Unlocked</Badge>;
      default:
        return <Badge variant="secondary">{status}</Badge>;
    }
  };

  const getStatusActions = (vault: VaultConfig, status: VaultStatus) => {
    const vaultId = vault.id;
    const isOperationLoading = operationLoading[vaultId];

    switch (status) {
      case 'Locked':
        return (
          <Button
            size="sm"
            onClick={() => handleUnlockVault(vault)}
            disabled={isOperationLoading}
          >
            {isOperationLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Unlock className="h-4 w-4" />}
            Unlock
          </Button>
        );
      case 'Unlocked':
        return (
          <Button
            size="sm"
            variant="outline"
            onClick={() => handleLockVault(vaultId)}
            disabled={isOperationLoading}
          >
            {isOperationLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Lock className="h-4 w-4" />}
            Lock
          </Button>
        );
      default:
        return null;
    }
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
      console.error("Vault creation error - Full error object:", err);
      console.error("Error type:", typeof err);
      console.error("Error constructor:", err?.constructor?.name);

      let errorMessage = "Unknown error occurred";

      if (err instanceof Error) {
        errorMessage = err.message;
        console.error("Error message:", err.message);
        console.error("Error stack:", err.stack);
      } else if (typeof err === 'string') {
        errorMessage = err;
      } else if (err && typeof err === 'object') {
        try {
          errorMessage = JSON.stringify(err, null, 2);
        } catch (jsonError) {
          errorMessage = String(err);
        }
      } else {
        errorMessage = String(err);
      }

      setError(`Failed to create vault: ${errorMessage}`);
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
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Configured Vaults</CardTitle>
                <CardDescription>
                  Manage your vault configurations and WebDAV access
                </CardDescription>
              </div>
              <Button onClick={loadVaultStatuses} variant="outline" size="sm">
                Refresh Status
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {vaults.map((vault: VaultConfig) => (
                <div
                  key={vault.id}
                  className="p-3 border rounded-lg border-gray-200"
                >
                  <div className="flex justify-between items-start">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h4 className="font-medium">{vault.name}</h4>
                        {getStatusBadge(vaultStatuses[vault.id] || 'Locked')}
                      </div>
                      <p className="text-sm text-gray-600">
                        Parent Directory: {vault.path}
                      </p>
                      <p className="text-sm text-gray-600">
                        Vault Directory: {vault.file_name}
                      </p>
                      <p className="text-sm text-gray-500">
                        Full path: {vault.path}/{vault.file_name}/
                      </p>

                      {/* WebDAV Mount Info */}
                      {vaultStatuses[vault.id] === 'Unlocked' && vaultMountUrls[vault.id] && (
                        <div className="flex items-center gap-2 text-sm text-green-600 mt-2">
                          <CheckCircle className="h-4 w-4" />
                          <span>Available via WebDAV</span>
                          <span className="text-xs text-gray-500">({vaultMountUrls[vault.id]})</span>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => copyMountUrl(vaultMountUrls[vault.id])}
                            className="h-6 px-2"
                            title="Copy WebDAV URL"
                          >
                            <Copy className="h-3 w-3" />
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => openInFinder(vaultMountUrls[vault.id], vault.name)}
                            className="h-6 px-2"
                            title="Open in Finder"
                          >
                            <ExternalLink className="h-3 w-3" />
                          </Button>
                        </div>
                      )}

                      {vault.last_accessed && (
                        <p className="text-sm text-gray-500 mt-1">
                          Last accessed: {new Date(vault.last_accessed).toLocaleString()}
                        </p>
                      )}
                    </div>
                    <div className="flex flex-col gap-2">
                      {/* WebDAV Actions */}
                      <div className="flex gap-2">
                        {getStatusActions(vault, vaultStatuses[vault.id] || 'Locked')}
                      </div>

                      {/* Vault Management Actions */}
                      <div className="flex gap-2">
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
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <PasswordDialog
        open={passwordDialogOpen}
        onOpenChange={setPasswordDialogOpen}
        onSubmit={handlePasswordSubmit}
        title={`Unlock ${selectedVault?.name}`}
        description="Enter your vault password to unlock and access your files."
        isLoading={isUnlocking}
        error={passwordError}
      />
    </div>
  );
}
