import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export function DebugFilePicker() {
  const [selectedPath, setSelectedPath] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleDirectoryPicker = async () => {
    try {
      setIsLoading(true);
      setError(null);
      console.log("Starting directory picker...");

      // Import the dialog module dynamically
      const { open } = await import("@tauri-apps/plugin-dialog");
      console.log("Dialog module imported successfully");

      const result = await open({
        directory: true,
        multiple: false,
        title: "Select Directory",
      });

      console.log("Dialog result:", result);

      if (result && typeof result === "string") {
        setSelectedPath(result);
        console.log("Selected path:", result);
      } else {
        console.log("No directory selected or cancelled");
      }
    } catch (err) {
      console.error("Error in directory picker:", err);
      setError(`Error: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleFilePicker = async () => {
    try {
      setIsLoading(true);
      setError(null);
      console.log("Starting file picker...");

      // Import the dialog module dynamically
      const { open } = await import("@tauri-apps/plugin-dialog");
      console.log("Dialog module imported successfully");

      const result = await open({
        directory: false,
        multiple: false,
        title: "Select File",
        filters: [
          {
            name: "All Files",
            extensions: ["*"],
          },
        ],
      });

      console.log("Dialog result:", result);

      if (result && typeof result === "string") {
        setSelectedPath(result);
        console.log("Selected path:", result);
      } else {
        console.log("No file selected or cancelled");
      }
    } catch (err) {
      console.error("Error in file picker:", err);
      setError(`Error: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Card className="w-full max-w-md">
      <CardHeader>
        <CardTitle>Debug File Picker</CardTitle>
        <CardDescription>
          Test the Tauri dialog functionality with detailed logging
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <Label htmlFor="selected-path">Selected Path</Label>
          <Input
            id="selected-path"
            value={selectedPath}
            onChange={(e) => setSelectedPath(e.target.value)}
            placeholder="No path selected..."
            className="mt-1"
          />
        </div>

        {error && (
          <div className="p-3 bg-red-100 border border-red-400 text-red-700 rounded text-sm">
            {error}
          </div>
        )}

        <div className="flex gap-2">
          <Button 
            onClick={handleDirectoryPicker} 
            disabled={isLoading}
            variant="outline"
            className="flex-1"
          >
            {isLoading ? "Loading..." : "Select Directory"}
          </Button>
          <Button 
            onClick={handleFilePicker} 
            disabled={isLoading}
            variant="outline"
            className="flex-1"
          >
            {isLoading ? "Loading..." : "Select File"}
          </Button>
        </div>

        {selectedPath && (
          <div className="p-3 bg-green-50 border border-green-200 rounded">
            <p className="text-sm text-green-800">
              <strong>Selected:</strong> {selectedPath}
            </p>
          </div>
        )}

        <div className="text-xs text-gray-500">
          <p>Check the browser console (F12) for detailed logs</p>
        </div>
      </CardContent>
    </Card>
  );
}
