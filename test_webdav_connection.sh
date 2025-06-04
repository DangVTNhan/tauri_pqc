#!/bin/bash

# Test script to demonstrate WebDAV connection workflow
echo "=== WebDAV Connection Test ==="
echo ""

# Step 1: Check if the Tauri app is running
echo "Step 1: Checking if Tauri app is running..."
if pgrep -f "tauri-app" > /dev/null; then
    echo "✅ Tauri app is running"
else
    echo "❌ Tauri app is not running. Please start it first with 'cargo tauri dev'"
    exit 1
fi

echo ""

# Step 2: Create a test vault directory
TEST_VAULT_DIR="$HOME/Desktop/test_vault"
echo "Step 2: Creating test vault directory at $TEST_VAULT_DIR"
mkdir -p "$TEST_VAULT_DIR"
echo "Hello from WebDAV!" > "$TEST_VAULT_DIR/test_file.txt"
echo "✅ Test vault directory created"

echo ""

# Step 3: Instructions for manual vault creation in the app
echo "Step 3: Manual steps to create and unlock vault in the Tauri app:"
echo "1. Open the Tauri app (should be running at http://localhost:1420/)"
echo "2. Click 'Create New Vault'"
echo "3. Set vault name: 'test_vault'"
echo "4. Set vault path: '$TEST_VAULT_DIR'"
echo "5. Set password: 'test123'"
echo "6. Click 'Create Vault'"
echo "7. The vault will be automatically unlocked and WebDAV server will start"

echo ""

# Step 4: Wait for user to complete vault creation
echo "Step 4: Waiting for vault to be unlocked..."
echo "Press ENTER after you have created and unlocked the vault in the app..."
read -r

echo ""

# Step 5: Test WebDAV server connection
echo "Step 5: Testing WebDAV server connection..."
echo "Testing connection to http://127.0.0.1:8080/test_vault/"

# Test with curl
if curl -u vault_user:vault_pass -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8080/test_vault/" | grep -q "200\|401\|207"; then
    echo "✅ WebDAV server is responding"
    
    # Try to list directory contents
    echo ""
    echo "Directory listing:"
    curl -u vault_user:vault_pass -X PROPFIND "http://127.0.0.1:8080/test_vault/" 2>/dev/null || echo "Could not list directory contents"
    
else
    echo "❌ WebDAV server is not responding"
    echo "Make sure the vault is unlocked in the app"
fi

echo ""

# Step 6: Instructions for Finder connection
echo "Step 6: Connect via macOS Finder:"
echo "1. Open Finder"
echo "2. Press Cmd+K (or Go > Connect to Server)"
echo "3. Enter URL: http://127.0.0.1:8080/test_vault/"
echo "4. Click 'Connect'"
echo "5. When prompted for credentials:"
echo "   - Username: vault_user"
echo "   - Password: vault_pass"
echo "6. The vault should mount as a network drive"

echo ""
echo "=== Test Complete ==="
echo "If you see any errors, check the Tauri app console for detailed logs."
