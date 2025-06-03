# E2EE Backend Server

A simple Go HTTP server backend for End-to-End Encrypted (E2EE) group file sharing.

## Features

- **User Registration** with E2EE key bundles
- **Group Management** for secure file sharing
- **File Sharing** with encryption metadata
- **In-Memory Storage** for prototyping
- **CORS Support** for web applications
- **Standard Library Only** - no external dependencies

## API Endpoints

### Authentication
- `POST /register` - Register a new user with E2EE key bundle

### Groups
- `POST /groups` - Create a new group
- `POST /groups/{groupId}/members` - Add a member to a group

### Files
- `POST /groups/{groupId}/files` - Share a file in a group
- `GET /groups/{groupId}/files` - List files in a group

### Health
- `GET /health` - Health check endpoint

## Running the Server

```bash
cd src-go
go run main.go
```

The server will start on port 8080 by default. You can set a custom port using the `PORT` environment variable:

```bash
PORT=3000 go run main.go
```

## Project Structure

```
src-go/
├── main.go              # Server entry point and routing
├── handlers/            # HTTP request handlers
│   ├── auth.go         # User registration
│   ├── groups.go       # Group management
│   └── files.go        # File sharing
├── models/             # Data structures
│   ├── user.go         # User model
│   ├── group.go        # Group model
│   ├── file.go         # File model
│   └── utils.go        # ID generation
├── storage/            # Storage layer
│   └── memory.go       # In-memory storage
├── middleware/         # HTTP middleware
│   └── cors.go         # CORS and logging
└── utils/              # Utilities
    ├── response.go     # JSON response helpers
    └── validation.go   # Input validation
```

## Example Usage

### Register a User
```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "SecurePass123",
    "key_bundle": {
      "identity_key": "base64encodedkey",
      "signed_pre_key": "base64encodedkey",
      "kyber_pre_key": "base64encodedkey",
      "one_time_pre_keys": ["base64encodedkey"],
      "signature": "base64encodedsig"
    }
  }'
```

### Create a Group
```bash
curl -X POST http://localhost:8080/groups \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Secure Group",
    "creator_id": "user-id-here"
  }'
```

### Share a File
```bash
curl -X POST http://localhost:8080/groups/{groupId}/files \
  -H "Content-Type: application/json" \
  -d '{
    "original_name": "document.pdf",
    "size": 1024000,
    "mime_type": "application/pdf",
    "shared_by": "user-id-here",
    "encrypted_data": "base64encrypteddata",
    "encryption_metadata": {
      "encryption_key": "base64key",
      "iv": "base64iv",
      "auth_tag": "base64tag",
      "chunk_size": 4096,
      "total_chunks": 250,
      "algorithm": "AES-256-GCM",
      "original_checksum": "base64checksum",
      "checksum_algorithm": "SHA-256"
    }
  }'
```

## Security Notes

- This is a prototype implementation using in-memory storage
- Password hashing uses SHA-256 (use bcrypt in production)
- No authentication tokens implemented (add JWT/sessions for production)
- CORS allows all origins (restrict in production)
- No rate limiting implemented
- No input sanitization beyond basic validation

## Integration with Tauri App

This backend is designed to work with your existing Tauri + React + TypeScript application. The API follows E2EE patterns compatible with your current vault system and supports the same data structures for users, groups, and files.
