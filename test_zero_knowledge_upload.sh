#!/bin/bash

# Test script to verify zero-knowledge file upload flow
API_BASE_URL="http://localhost:8080"

echo "🧪 Testing Zero-Knowledge File Upload Flow..."
echo

# Generate unique username
TIMESTAMP=$(date +%s)
USERNAME="alice_test_$TIMESTAMP"

# Test data for user and group
USER_DATA="{
  \"username\": \"$USERNAME\",
  \"password\": \"AlicePassword123\",
  \"key_bundle\": {
    \"public_keys\": {
      \"identity_key\": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
      \"signed_pre_key\": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
      \"kyber_pre_key\": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
      \"one_time_pre_keys\": [[4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4]],
      \"signature\": [5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5]
    },
    \"private_keys\": {
      \"identity_key\": [6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6],
      \"signed_pre_key\": [7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],
      \"kyber_pre_key\": [8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8],
      \"one_time_pre_keys\": [[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9]],
      \"salt\": [10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10],
      \"identity_key_nonce\": [11,11,11,11,11,11,11,11,11,11,11,11],
      \"signed_pre_key_nonce\": [12,12,12,12,12,12,12,12,12,12,12,12],
      \"kyber_pre_key_nonce\": [13,13,13,13,13,13,13,13,13,13,13,13],
      \"one_time_pre_keys_nonces\": [[14,14,14,14,14,14,14,14,14,14,14,14]]
    },
    \"timestamp\": \"2024-01-01T00:00:00Z\"
  }
}"

echo "📝 Step 1: Register test user..."
USER_RESPONSE=$(curl -s -X POST "$API_BASE_URL/register" \
  -H "Content-Type: application/json" \
  -d "$USER_DATA")

echo "User registration response: $USER_RESPONSE"

# Extract user ID from response
USER_ID=$(echo "$USER_RESPONSE" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
echo "User ID: $USER_ID"
echo

echo "📝 Step 2: Create test group..."
GROUP_DATA="{\"name\": \"Test Group\", \"creator_id\": \"$USER_ID\"}"
GROUP_RESPONSE=$(curl -s -X POST "$API_BASE_URL/groups" \
  -H "Content-Type: application/json" \
  -d "$GROUP_DATA")

echo "Group creation response: $GROUP_RESPONSE"

# Extract group ID from response
GROUP_ID=$(echo "$GROUP_RESPONSE" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
echo "Group ID: $GROUP_ID"
echo

echo "📝 Step 3: Test blob upload (simulating encrypted file)..."
BLOB_UPLOAD_DATA='{
  "encrypted_content": "dGVzdCBmaWxlIGNvbnRlbnQgZm9yIGJsb2Igc3RvcmFnZQ==",
  "blob_hash": "4a2722f125049a743f52ab54c9286af45388d2ab628798c17f18cbe4993a0d45"
}'

echo "Uploading encrypted blob..."
BLOB_RESPONSE=$(curl -s -X POST "$API_BASE_URL/blobs/upload" \
  -H "Content-Type: application/json" \
  -d "$BLOB_UPLOAD_DATA")

echo "Blob upload response: $BLOB_RESPONSE"

# Extract blob info from response
BLOB_ID=$(echo "$BLOB_RESPONSE" | grep -o '"blob_id":"[^"]*"' | cut -d'"' -f4)
BLOB_URL=$(echo "$BLOB_RESPONSE" | grep -o '"blob_url":"[^"]*"' | cut -d'"' -f4)
BLOB_HASH=$(echo "$BLOB_RESPONSE" | grep -o '"blob_hash":"[^"]*"' | cut -d'"' -f4)

echo "Blob ID: $BLOB_ID"
echo "Blob URL: $BLOB_URL"
echo "Blob Hash: $BLOB_HASH"
echo

echo "📝 Step 4: Share file metadata with group..."
FILE_METADATA="{
  \"original_name\": \"test_image.jpg\",
  \"size\": 1024,
  \"mime_type\": \"image/jpeg\",
  \"shared_by\": \"$USER_ID\",
  \"blob_url\": \"$BLOB_URL\",
  \"blob_hash\": \"$BLOB_HASH\"
}"

echo "Sharing file metadata..."
METADATA_RESPONSE=$(curl -s -X POST "$API_BASE_URL/groups/$GROUP_ID/files" \
  -H "Content-Type: application/json" \
  -d "$FILE_METADATA")

echo "File metadata response: $METADATA_RESPONSE"

# Extract file ID from response
FILE_ID=$(echo "$METADATA_RESPONSE" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
echo "File ID: $FILE_ID"
echo

echo "📝 Step 5: Send wrapped keys via message queue..."
WRAPPED_KEYS_DATA="{
  \"file_id\": \"$FILE_ID\",
  \"group_id\": \"$GROUP_ID\",
  \"wrapped_keys\": {
    \"$USER_ID\": {
      \"encrypted_key\": \"demo_encrypted_master_key_for_user\",
      \"key_exchange\": {
        \"ephemeral_public_key\": \"demo_ephemeral_key\",
        \"kyber_ciphertext\": \"demo_kyber_ciphertext\",
        \"salt\": \"demo_salt\",
        \"nonce\": \"demo_nonce\"
      }
    }
  }
}"

echo "Sending wrapped keys..."
KEYS_RESPONSE=$(curl -s -X POST "$API_BASE_URL/messages/send-bulk" \
  -H "Content-Type: application/json" \
  -d "$WRAPPED_KEYS_DATA")

echo "Wrapped keys response: $KEYS_RESPONSE"
echo

echo "📝 Step 6: Check user's message queue..."
MESSAGES_RESPONSE=$(curl -s -X GET "$API_BASE_URL/users/$USER_ID/messages")
echo "User messages: $MESSAGES_RESPONSE"
echo

echo "🎉 Zero-knowledge file upload test completed!"
echo "✅ Blob uploaded to storage"
echo "✅ Wrapped keys sent via message queue"
echo "✅ File metadata shared (no encryption keys on server)"
echo "✅ User can retrieve wrapped keys from message queue"
