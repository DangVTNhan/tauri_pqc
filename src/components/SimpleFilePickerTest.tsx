import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { open } from "@tauri-apps/plugin-dialog";

export function SimpleFilePickerTest() {
  const [selectedPath, setSelectedPath] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const handleSelectDirectory = async () => {
    try {
      setIsLoading(true);
      const result = await open({
        directory: true,
        multiple: false,
        title: "Select Directory",
      });

      if (result && typeof result === "string") {
        setSelectedPath(result);
      }
    } catch (error) {
      console.error("Error selecting directory:", error);
      alert("Error selecting directory: " + error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSelectFile = async () => {
    try {
      setIsLoading(true);
      const result = await open({
        directory: false,
        multiple: false,
        title: "Select File",
        filters: [
          {
            name: "Database Files",
            extensions: ["db", "sqlite", "sqlite3"],
          },
          {
            name: "All Files",
            extensions: ["*"],
          },
        ],
      });

      if (result && typeof result === "string") {
        setSelectedPath(result);
      }
    } catch (error) {
      console.error("Error selecting file:", error);
      alert("Error selecting file: " + error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Card className="w-full max-w-md">
      <CardHeader>
        <CardTitle>File Picker Test</CardTitle>
        <CardDescription>
          Test the Tauri file dialog functionality
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

        <div className="flex gap-2">
          <Button 
            onClick={handleSelectDirectory} 
            disabled={isLoading}
            variant="outline"
            className="flex-1"
          >
            {isLoading ? "Loading..." : "Select Directory"}
          </Button>
          <Button 
            onClick={handleSelectFile} 
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
      </CardContent>
    </Card>
  );
}
