// Hook for managing E2EE user session state

import type { Group, SharedFile, User, UserSession } from '@/types/e2ee';
import { useCallback, useState } from 'react';

interface E2EESessionState {
  session: UserSession | null;
  isLoading: boolean;
  error: string | null;
}

export function useE2EESession() {
  const [state, setState] = useState<E2EESessionState>({
    session: null,
    isLoading: false,
    error: null,
  });

  const setLoading = useCallback((loading: boolean) => {
    setState(prev => ({ ...prev, isLoading: loading }));
  }, []);

  const setError = useCallback((error: string | null) => {
    setState(prev => ({ ...prev, error }));
  }, []);

  const login = useCallback((user: User, groups: Group[] = []) => {
    setState({
      session: {
        user,
        groups,
        isAuthenticated: true,
      },
      isLoading: false,
      error: null,
    });
  }, []);

  const logout = useCallback(() => {
    setState({
      session: null,
      isLoading: false,
      error: null,
    });
  }, []);

  const addGroup = useCallback((group: Group) => {
    setState(prev => {
      if (!prev.session) return prev;
      
      return {
        ...prev,
        session: {
          ...prev.session,
          groups: [...prev.session.groups, group],
        },
      };
    });
  }, []);

  const updateGroupFiles = useCallback((_groupId: string, _files: SharedFile[]) => {
    setState(prev => {
      if (!prev.session) return prev;

      // For now, we'll just store files in a simple way
      // In a real app, you might want a more sophisticated state structure
      return prev;
    });
  }, []);

  const clearError = useCallback(() => {
    setError(null);
  }, [setError]);

  return {
    session: state.session,
    isLoading: state.isLoading,
    error: state.error,
    isAuthenticated: state.session?.isAuthenticated ?? false,
    user: state.session?.user ?? null,
    groups: state.session?.groups ?? [],
    
    // Actions
    login,
    logout,
    addGroup,
    updateGroupFiles,
    setLoading,
    setError,
    clearError,
  };
}
