import { ConfigDemo } from "@/components/ConfigDemo";
import { invoke } from "@tauri-apps/api/core";
import { useState } from "react";

function App() {
  const [greetMsg, setGreetMsg] = useState("");
  const [name, setName] = useState("");

  async function greetMultiParam() {
    // Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
    setGreetMsg(await invoke("greet_multi_param", { name, age: 20 }));
  }

  return (
    <main className="min-h-screen bg-background text-foreground flex flex-col items-center justify-center p-8">
      <div className="w-full max-w-6xl space-y-8">
        <div className="flex justify-center">
          <ConfigDemo />
        </div>
      </div>
    </main>
  );
}

export default App;
