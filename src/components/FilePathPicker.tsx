import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { FolderOpen, File } from "lucide-react";
import { open } from "@tauri-apps/plugin-dialog";

interface FilePathPickerProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  type?: "file" | "directory";
  filters?: Array<{
    name: string;
    extensions: string[];
  }>;
  disabled?: boolean;
  className?: string;
}

export function FilePathPicker({
  label,
  value,
  onChange,
  placeholder = "Select a path...",
  type = "directory",
  filters,
  disabled = false,
  className = "",
}: FilePathPickerProps) {
  const [isPickerOpen, setIsPickerOpen] = useState(false);

  const handleBrowse = async () => {
    try {
      setIsPickerOpen(true);
      
      let selectedPath: string | null = null;

      if (type === "directory") {
        selectedPath = await open({
          directory: true,
          multiple: false,
          title: `Select ${label}`,
        });
      } else {
        selectedPath = await open({
          directory: false,
          multiple: false,
          title: `Select ${label}`,
          filters: filters || [
            {
              name: "All Files",
              extensions: ["*"],
            },
          ],
        });
      }

      if (selectedPath && typeof selectedPath === "string") {
        onChange(selectedPath);
      }
    } catch (error) {
      console.error("Error opening file picker:", error);
    } finally {
      setIsPickerOpen(false);
    }
  };

  return (
    <div className={`space-y-2 ${className}`}>
      <Label htmlFor={`path-${label}`}>{label}</Label>
      <div className="flex gap-2">
        <Input
          id={`path-${label}`}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          disabled={disabled}
          className="flex-1"
        />
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={handleBrowse}
          disabled={disabled || isPickerOpen}
          className="px-3"
        >
          {isPickerOpen ? (
            <div className="w-4 h-4 animate-spin rounded-full border-2 border-gray-300 border-t-gray-600" />
          ) : type === "directory" ? (
            <FolderOpen className="w-4 h-4" />
          ) : (
            <File className="w-4 h-4" />
          )}
        </Button>
      </div>
      {value && (
        <p className="text-xs text-gray-500 break-all">
          Selected: {value}
        </p>
      )}
    </div>
  );
}

// Specialized components for common use cases
export function DirectoryPicker(props: Omit<FilePathPickerProps, "type">) {
  return <FilePathPicker {...props} type="directory" />;
}

export function FilePicker(props: Omit<FilePathPickerProps, "type">) {
  return <FilePathPicker {...props} type="file" />;
}

// Database file picker with specific filters
export function DatabaseFilePicker(props: Omit<FilePathPickerProps, "type" | "filters">) {
  return (
    <FilePathPicker
      {...props}
      type="file"
      filters={[
        {
          name: "Database Files",
          extensions: ["db", "sqlite", "sqlite3"],
        },
        {
          name: "All Files",
          extensions: ["*"],
        },
      ]}
    />
  );
}

// Vault file picker with specific filters
export function VaultFilePicker(props: Omit<FilePathPickerProps, "type" | "filters">) {
  return (
    <FilePathPicker
      {...props}
      type="file"
      filters={[
        {
          name: "Vault Files",
          extensions: ["vault", "db", "encrypted"],
        },
        {
          name: "Database Files",
          extensions: ["db", "sqlite", "sqlite3"],
        },
        {
          name: "All Files",
          extensions: ["*"],
        },
      ]}
    />
  );
}
