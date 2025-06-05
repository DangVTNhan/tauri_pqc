import { Card, CardContent } from "@/components/ui/card";
import { VaultManager } from "@/components/VaultManager";
import { configManager } from "@/lib/config";
import type { AppConfig } from "@/types/config";
import { useEffect, useState } from "react";

export function ConfigDemo() {
  const [config, setConfig] = useState<AppConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadConfiguration();
  }, []);

  const loadConfiguration = async () => {
    try {
      setLoading(true);
      setError(null);
      const loadedConfig = await configManager.loadConfig();
      setConfig(loadedConfig);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load configuration");
    } finally {
      setLoading(false);
    }
  };



  if (loading) {
    return (
      <Card className="w-full max-w-4xl">
        <CardContent className="p-6">
          <div className="text-center">Loading configuration...</div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="w-full max-w-4xl space-y-6">
      {error && (
        <div className="p-3 bg-red-100 border border-red-400 text-red-700 rounded">
          {error}
        </div>
      )}

      {/* Vault Management */}
      <VaultManager
        vaults={config?.vaults || []}
        onVaultUpdate={loadConfiguration}
      />
    </div>
  );
}
