import { invoke } from "@tauri-apps/api/core";
import { useState } from "react";
import reactLogo from "./assets/react.svg";

function App() {
  const [greetMsg, setGreetMsg] = useState("");
  const [name, setName] = useState("");

  async function greetMultiParam() {
    // Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
    setGreetMsg(await invoke("greet_multi_param", { name, age: 20 }));
  }

  return (
    <main className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100 flex flex-col items-center justify-center p-8">
      <h1 className="text-4xl font-bold text-center mb-8">Welcome to Tauri + React</h1>

      <div className="flex items-center justify-center gap-8 mb-8">
        <a
          href="https://vitejs.dev"
          target="_blank"
          className="transition-all duration-300 hover:drop-shadow-[0_0_2em_#747bff]"
        >
          <img src="/vite.svg" className="h-24 w-24" alt="Vite logo" />
        </a>
        <a
          href="https://tauri.app"
          target="_blank"
          className="transition-all duration-300 hover:drop-shadow-[0_0_2em_#24c8db]"
        >
          <img src="/tauri.svg" className="h-24 w-24" alt="Tauri logo" />
        </a>
        <a
          href="https://reactjs.org"
          target="_blank"
          className="transition-all duration-300 hover:drop-shadow-[0_0_2em_#61dafb]"
        >
          <img src={reactLogo} className="h-24 w-24 animate-spin" alt="React logo" />
        </a>
      </div>

      <p className="text-gray-600 dark:text-gray-400 mb-8 text-center">
        Click on the Tauri, Vite, and React logos to learn more.
      </p>

      <form
        className="flex items-center gap-4 mb-4"
        onSubmit={(e) => {
          e.preventDefault();
          greetMultiParam();
        }}
      >
        <input
          id="greet-input"
          onChange={(e) => setName(e.currentTarget.value)}
          placeholder="Enter a name..."
          className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder:text-gray-500 dark:placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
        />
        <button
          type="submit"
          className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-colors font-medium"
        >
          Greet
        </button>
      </form>

      {greetMsg && (
        <p className="text-lg font-medium text-blue-600 dark:text-blue-400">{greetMsg}</p>
      )}
    </main>
  );
}

export default App;
