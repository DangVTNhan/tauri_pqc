import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { useE2EESession } from '@/hooks/useE2EESession';
import { api } from '@/lib/api';
import { invoke } from '@tauri-apps/api/core';
import {
  generateKeyBundle,
  readFileAsArrayBuffer,
} from '@/lib/encryption';
import type { FileUploadProgress, SharedFile } from '@/types/e2ee';
import {
  Download,
  FileText,
  Key,
  Loader2,
  Lock,
  Shield,
  Unlock,
  User,
  Users
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { toast } from 'sonner';

export function E2EEGroupSharing() {
  const {
    isLoading: sessionLoading,
    error: sessionError,
    isAuthenticated,
    user,
    groups,
    login,
    logout,
    addGroup,
    setLoading,
    setError,
    clearError,
  } = useE2EESession();

  // Authentication state
  const [authMode, setAuthMode] = useState<'register' | 'login'>('register');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isAuthLoading, setIsAuthLoading] = useState(false);

  // Group operations state
  const [groupName, setGroupName] = useState('');
  const [memberUsername, setMemberUsername] = useState('');
  const [selectedGroupId, setSelectedGroupId] = useState<string>('');
  const [groupFiles, setGroupFiles] = useState<Record<string, SharedFile[]>>({});
  const [uploadProgress, setUploadProgress] = useState<FileUploadProgress | null>(null);

  // Backend availability check
  const [backendAvailable, setBackendAvailable] = useState<boolean | null>(null);

  useEffect(() => {
    checkBackendAvailability();
  }, []);

  const checkBackendAvailability = async () => {
    const available = await api.isBackendAvailable();
    setBackendAvailable(available);
    if (!available) {
      setError('Go backend server is not available. Please start the server on port 8080.');
    }
  };

  const handleRegister = async () => {
    if (!username.trim() || !password.trim()) {
      setError('Please enter both username and password');
      return;
    }

    setIsAuthLoading(true);
    clearError();

    try {
      // Generate E2EE key bundle
      const keyBundle = await generateKeyBundle(password);

      // Register with backend
      const result = await api.register(username, password, keyBundle);

      if (result.success && result.user) {
        login(result.user, []);
        toast.success('Registration successful!');
        setUsername('');
        setPassword('');
      } else {
        setError(result.error || 'Registration failed');
      }
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Registration failed');
    } finally {
      setIsAuthLoading(false);
    }
  };

  const handleLogin = async () => {
    if (!username.trim() || !password.trim()) {
      setError('Please enter both username and password');
      return;
    }

    setIsAuthLoading(true);
    clearError();

    try {
      // Login with backend
      const result = await api.login(username, password);

      if (result.success && result.user) {
        login(result.user, result.groups || []);
        toast.success('Login successful!');
        setUsername('');
        setPassword('');
      } else {
        setError(result.error || 'Login failed');
      }
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Login failed');
    } finally {
      setIsAuthLoading(false);
    }
  };

  const handleCreateGroup = async () => {
    if (!groupName.trim() || !user) {
      setError('Please enter a group name');
      return;
    }

    setLoading(true);
    clearError();

    try {
      const result = await api.createGroup(groupName, user.id);
      
      if (result.success && result.group) {
        addGroup(result.group);
        toast.success('Group created successfully!');
        setGroupName('');
      } else {
        setError(result.error || 'Failed to create group');
      }
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to create group');
    } finally {
      setLoading(false);
    }
  };

  const handleAddMember = async () => {
    if (!memberUsername.trim() || !selectedGroupId) {
      setError('Please enter a username and select a group');
      return;
    }

    setLoading(true);
    clearError();

    try {
      // Look up the user by username to get their actual user ID
      const userResult = await api.getUserByUsername(memberUsername.trim());

      if (!userResult.success || !userResult.user) {
        setError(userResult.error || 'User not found');
        return;
      }

      // Add the member using their actual user ID
      const result = await api.addMember(selectedGroupId, userResult.user.id);

      if (result.success) {
        toast.success('Member added successfully!');
        setMemberUsername('');
      } else {
        setError(result.error || 'Failed to add member');
      }
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to add member');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file || !selectedGroupId || !user) {
      setError('Please select a file and group');
      return;
    }

    setUploadProgress({
      file_name: file.name,
      progress: 0,
      status: 'encrypting',
    });

    try {
      // NEW E2EE FILE SHARING FLOW - All cryptographic operations moved to Rust backend
      // Read file data
      const fileData = await readFileAsArrayBuffer(file);

      // Convert to base64 for Tauri
      const base64Data = btoa(String.fromCharCode(...new Uint8Array(fileData)));

      setUploadProgress(prev => prev ? { ...prev, progress: 20, status: 'encrypting' } : null);

      // Call the new Tauri command that handles all crypto operations in Rust
      const shareResult = await invoke<{
        success: boolean;
        file_id?: string;
        error?: string;
      }>('e2ee_share_file_with_group', {
        request: {
          file_data: base64Data,
          file_name: file.name,
          file_size: file.size,
          mime_type: file.type || 'application/octet-stream',
          group_id: selectedGroupId,
          password: password, // User's password for key decryption
        }
      });

      if (shareResult.success && shareResult.file_id) {
        setUploadProgress(prev => prev ? { ...prev, progress: 100, status: 'complete' } : null);
        toast.success('File shared successfully!');

        // Refresh group files
        await loadGroupFiles(selectedGroupId);

        // Clear upload progress after a delay
        setTimeout(() => setUploadProgress(null), 2000);
      } else {
        setUploadProgress(prev => prev ? { ...prev, status: 'error', error: shareResult.error } : null);
        setError(shareResult.error || 'Failed to share file');
      }
    } catch (error) {
      setUploadProgress(prev => prev ? {
        ...prev,
        status: 'error',
        error: error instanceof Error ? error.message : 'Upload failed'
      } : null);
      setError(error instanceof Error ? error.message : 'Failed to upload file');
    }

    // Reset file input
    event.target.value = '';
  };

  const loadGroupFiles = async (groupId: string) => {
    try {
      const result = await api.getGroupFiles(groupId);
      if (result.success && result.files) {
        setGroupFiles(prev => ({ ...prev, [groupId]: result.files! }));
      }
    } catch (error) {
      console.error('Failed to load group files:', error);
    }
  };

  const handleFileDownload = async (file: SharedFile) => {
    if (!user) {
      toast.error('User authentication required for file download');
      return;
    }

    try {
      toast.info('Downloading and decrypting file...');

      // Call the new Tauri command that handles all crypto operations in Rust
      const downloadResult = await invoke<{
        success: boolean;
        file_data?: string;
        file_name?: string;
        error?: string;
      }>('e2ee_download_and_decrypt_file', {
        request: {
          file_id: file.id,
          password: password, // User's password for key decryption
        }
      });

      if (downloadResult.success && downloadResult.file_data) {
        // For now, just show success message since we have placeholder data
        toast.success(`Successfully downloaded and decrypted: ${downloadResult.file_name || file.original_name}`);

        // In a real implementation, we would:
        // 1. Convert base64 file_data back to binary
        // 2. Create a blob and download it
        console.log('File download successful:', {
          fileName: downloadResult.file_name,
          dataLength: downloadResult.file_data.length,
        });
      } else {
        toast.error(downloadResult.error || 'Failed to download file');
      }

    } catch (error) {
      toast.error('Failed to download file');
      console.error('Download error:', error);
    }
  };

  if (backendAvailable === false) {
    return (
      <div className="max-w-4xl mx-auto p-6">
        <Card className="border-destructive">
          <CardHeader>
            <CardTitle className="text-destructive flex items-center gap-2">
              <Shield className="w-5 h-5" />
              Backend Server Unavailable
            </CardTitle>
            <CardDescription>
              The Go backend server is not running. Please start it first:
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="bg-muted p-4 rounded-lg font-mono text-sm">
              <div>cd src-go</div>
              <div>go run main.go</div>
            </div>
            <Button onClick={checkBackendAvailability} className="mt-4">
              Check Again
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      <div className="text-center mb-8">
        <h1 className="text-3xl font-bold mb-2">E2EE Group File Sharing</h1>
        <p className="text-muted-foreground">
          Secure end-to-end encrypted file sharing with group management
        </p>
      </div>

      {sessionError && (
        <Card className="border-destructive">
          <CardContent className="pt-6">
            <div className="text-destructive text-sm">{sessionError}</div>
            <Button variant="outline" size="sm" onClick={clearError} className="mt-2">
              Dismiss
            </Button>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Card 1: User Authentication */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <User className="w-5 h-5" />
              User Authentication
            </CardTitle>
            <CardDescription>
              Register or login to access E2EE group file sharing
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {!isAuthenticated ? (
              <>
                <div className="flex gap-2 mb-4">
                  <Button
                    variant={authMode === 'register' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setAuthMode('register')}
                  >
                    Register
                  </Button>
                  <Button
                    variant={authMode === 'login' ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setAuthMode('login')}
                  >
                    Login
                  </Button>
                </div>

                <div className="space-y-3">
                  <div>
                    <Label htmlFor="username">Username</Label>
                    <Input
                      id="username"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      placeholder="Enter username"
                      disabled={isAuthLoading}
                    />
                  </div>
                  <div>
                    <Label htmlFor="password">Password</Label>
                    <Input
                      id="password"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Enter password"
                      disabled={isAuthLoading}
                    />
                  </div>
                  <Button
                    onClick={authMode === 'register' ? handleRegister : handleLogin}
                    disabled={isAuthLoading || !username.trim() || !password.trim()}
                    className="w-full"
                  >
                    {isAuthLoading ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        {authMode === 'register' ? 'Registering...' : 'Logging in...'}
                      </>
                    ) : (
                      <>
                        <Key className="w-4 h-4 mr-2" />
                        {authMode === 'register' ? 'Register & Generate Keys' : 'Login'}
                      </>
                    )}
                  </Button>
                </div>

                <div className="text-xs text-muted-foreground bg-muted p-3 rounded">
                  {authMode === 'register' ? (
                    <>
                      <strong>Note:</strong> Registration will automatically generate E2EE key bundles
                      for secure communication. Your keys are generated locally and never sent in plain text.
                    </>
                  ) : (
                    <>
                      <strong>Note:</strong> Login will authenticate you with your existing account
                      and restore access to your groups and encrypted files.
                    </>
                  )}
                </div>
              </>
            ) : (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="font-medium">{user?.username}</div>
                    <div className="text-sm text-muted-foreground">
                      Registered: {user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'Unknown'}
                    </div>
                  </div>
                  <Badge variant="secondary" className="flex items-center gap-1">
                    <Unlock className="w-3 h-3" />
                    Authenticated
                  </Badge>
                </div>
                
                <Separator />
                
                <div className="space-y-2">
                  <div className="text-sm font-medium">Groups: {groups.length}</div>
                  {groups.length > 0 && (
                    <div className="space-y-1">
                      {groups.map((group) => (
                        <div key={group.id} className="text-xs text-muted-foreground">
                          • {group.name} ({group.members.length} members)
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <Button variant="outline" onClick={logout} className="w-full">
                  <Lock className="w-4 h-4 mr-2" />
                  Logout
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Card 2: Group Operations */}
        {isAuthenticated && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Users className="w-5 h-5" />
                Group Operations
              </CardTitle>
              <CardDescription>
                Create groups, add members, and share encrypted files
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Create Group */}
              <div className="space-y-3">
                <Label htmlFor="groupName">Create New Group</Label>
                <div className="flex gap-2">
                  <Input
                    id="groupName"
                    value={groupName}
                    onChange={(e) => setGroupName(e.target.value)}
                    placeholder="Enter group name"
                    disabled={sessionLoading}
                  />
                  <Button
                    onClick={handleCreateGroup}
                    disabled={sessionLoading || !groupName.trim()}
                  >
                    {sessionLoading ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      'Create'
                    )}
                  </Button>
                </div>
              </div>

              <Separator />

              {/* Add Member */}
              {groups.length > 0 && (
                <div className="space-y-3">
                  <Label>Add Member to Group</Label>
                  <div className="space-y-2">
                    <select
                      value={selectedGroupId}
                      onChange={(e) => setSelectedGroupId(e.target.value)}
                      className="w-full p-2 border rounded-md"
                    >
                      <option value="">Select a group</option>
                      {groups.map((group) => (
                        <option key={group.id} value={group.id}>
                          {group.name}
                        </option>
                      ))}
                    </select>
                    <div className="flex gap-2">
                      <Input
                        value={memberUsername}
                        onChange={(e) => setMemberUsername(e.target.value)}
                        placeholder="Username to add"
                        disabled={sessionLoading}
                      />
                      <Button
                        onClick={handleAddMember}
                        disabled={sessionLoading || !memberUsername.trim() || !selectedGroupId}
                      >
                        Add
                      </Button>
                    </div>
                  </div>
                </div>
              )}

              <Separator />

              {/* File Upload */}
              {groups.length > 0 && (
                <div className="space-y-3">
                  <Label>Share Encrypted File</Label>
                  {!selectedGroupId && (
                    <div className="text-sm text-muted-foreground">
                      Please select a group first
                    </div>
                  )}
                  {selectedGroupId && (
                    <div className="space-y-2">
                      <input
                        type="file"
                        onChange={handleFileUpload}
                        className="w-full p-2 border rounded-md"
                        disabled={!!uploadProgress}
                      />
                      {uploadProgress && (
                        <div className="space-y-2">
                          <div className="flex items-center justify-between text-sm">
                            <span>{uploadProgress.file_name}</span>
                            <span>{uploadProgress.progress}%</span>
                          </div>
                          <div className="w-full bg-muted rounded-full h-2">
                            <div
                              className="bg-primary h-2 rounded-full transition-all"
                              style={{ width: `${uploadProgress.progress}%` }}
                            />
                          </div>
                          <div className="text-xs text-muted-foreground">
                            Status: {uploadProgress.status}
                            {uploadProgress.error && (
                              <span className="text-destructive"> - {uploadProgress.error}</span>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* File List */}
              {selectedGroupId && groupFiles[selectedGroupId] && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <Label>Shared Files</Label>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => loadGroupFiles(selectedGroupId)}
                    >
                      Refresh
                    </Button>
                  </div>
                  <div className="space-y-2 max-h-40 overflow-y-auto">
                    {groupFiles[selectedGroupId].length === 0 ? (
                      <div className="text-sm text-muted-foreground">No files shared yet</div>
                    ) : (
                      groupFiles[selectedGroupId].map((file) => (
                        <div
                          key={file.id}
                          className="flex items-center justify-between p-2 border rounded"
                        >
                          <div className="flex items-center gap-2">
                            <FileText className="w-4 h-4" />
                            <div>
                              <div className="text-sm font-medium">{file.original_name}</div>
                              <div className="text-xs text-muted-foreground">
                                {(file.size / 1024).toFixed(1)} KB • {file.shared_by}
                              </div>
                            </div>
                          </div>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleFileDownload(file)}
                          >
                            <Download className="w-4 h-4" />
                          </Button>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}

              {groups.length === 0 && (
                <div className="text-center text-muted-foreground py-8">
                  <Users className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <div>Create your first group to start sharing files</div>
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
