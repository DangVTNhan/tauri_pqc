import { ConfigDemo } from "@/components/ConfigDemo";

function App() {
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
