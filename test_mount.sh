#!/bin/bash

# Test script to verify WebDAV mounting functionality

echo "Testing WebDAV mounting functionality..."

# Test the simplified AppleScript
echo "Testing simplified mount AppleScript..."

osascript -e '
set mountURL to "http://localhost:8080/"
set mountName to "TestVault"
try
    mount volume mountURL
    delay 2
    tell application "Finder" to set name of disk mountURL to mountName
    return "success"
on error errMsg
    return "error: " & errMsg
end try
'

echo "AppleScript test completed."

# Check if any volumes are mounted
echo "Checking mounted volumes..."
ls -la /Volumes/

echo "Test completed."
