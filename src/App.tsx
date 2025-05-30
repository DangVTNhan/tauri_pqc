import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
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
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Greet Function</CardTitle>
          <CardDescription>
            Test the Tauri backend integration with Shadcn UI components
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-col gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              greetMultiParam();
            }}
          >
            <Input
              id="greet-input"
              value={name}
              onChange={(e) => setName(e.currentTarget.value)}
              placeholder="Enter a name..."
            />
            <Button type="submit" className="w-full">
              Greet
            </Button>
          </form>

          {greetMsg && (
            <p className="text-lg font-medium text-primary mt-4 text-center">{greetMsg}</p>
          )}
        </CardContent>
      </Card>
    </main>
  );
}

export default App;
