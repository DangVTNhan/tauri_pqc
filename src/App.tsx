import { ConfigDemo } from "@/components/VaultManagerWrapper";
// import { E2EEDemo } from "@/components/E2EEDemo";
import { Button } from "@/components/ui/button";
import { useState } from "react";
import { Toaster } from "sonner";
import { E2EEGroupSharing } from "./components/E2EEGroupSharing";

function App() {
  const [activeTab, setActiveTab] = useState<'sharing' | 'config'>('sharing');

  return (
    <main className="min-h-screen bg-background text-foreground">
      <div className="container mx-auto p-4">
        <div className="flex justify-center mb-6">
          <div className="flex gap-2">
            <Button
              variant={activeTab === 'sharing' ? "default" : "outline"}
              onClick={() => setActiveTab('sharing')}
            >
              Group File Sharing
            </Button>
            {/* <Button
              variant={activeTab === 'test' ? "default" : "outline"}
              onClick={() => setActiveTab('test')}
            >
              System Test
            </Button> */}
            <Button
              variant={activeTab === 'config' ? "default" : "outline"}
              onClick={() => setActiveTab('config')}
            >
              My Vault
            </Button>
          </div>
        </div>

        {activeTab === 'sharing' && <E2EEGroupSharing />}
        {/* {activeTab === 'test' && <E2EEDemo />} */}
        {activeTab === 'config' && <ConfigDemo />}
      </div>
      <Toaster position="top-right" />
    </main>
  );
}

export default App;
