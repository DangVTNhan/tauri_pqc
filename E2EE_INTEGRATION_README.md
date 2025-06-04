# E2EE Group File Sharing Integration

This document describes the complete integration between the Tauri frontend and Go backend for End-to-End Encrypted (E2EE) group file sharing.

## 🏗️ Architecture Overview

### Frontend (Tauri + React + TypeScript)
- **E2EE Component**: Single-page interface with authentication and group operations
- **Encryption Layer**: Uses Tauri's Rust encryption APIs for file encryption/decryption
- **API Client**: Communicates with Go backend via HTTP
- **State Management**: Simple React hooks for session and file management

### Backend (Go HTTP Server)
- **RESTful API**: Standard HTTP endpoints for user, group, and file operations
- **In-Memory Storage**: Prototype-ready storage using Go maps/slices
- **E2EE Support**: Handles encrypted file data and metadata
- **Standard Library Only**: No external dependencies

## 🚀 Getting Started

### 1. Start the Go Backend
```bash
cd src-go
go run main.go
```
The server will start on `http://localhost:8080`

### 2. Start the Tauri Frontend
```bash
npm run tauri dev
```

### 3. Test the Integration
1. Open the application
2. Click "System Test" to run automated tests
3. Or use "E2EE Group Sharing" for manual testing

## 📋 Features Implemented

### ✅ User Authentication
- **Registration**: Username/password with auto-generated E2EE key bundles
- **Key Generation**: Post-quantum cryptographic keys (identity, signed pre-key, Kyber, one-time keys)
- **Session Management**: Frontend state management for authenticated users

### ✅ Group Management
- **Group Creation**: Create secure groups for file sharing
- **Member Management**: Add users to groups (demo implementation)
- **Group Listing**: Display user's group memberships

### ✅ File Sharing
- **File Encryption**: Client-side encryption using Tauri's AES-256-GCM
- **Secure Upload**: Only encrypted data sent to backend
- **File Metadata**: Encryption parameters stored with files
- **File Listing**: Display shared files in groups
- **Download Preparation**: Framework for decrypting downloaded files

### ✅ Security Features
- **E2EE Key Bundles**: Post-quantum cryptographic key generation
- **Client-Side Encryption**: Files encrypted before leaving the device
- **Metadata Protection**: Encryption keys and IVs properly managed
- **In-Memory Processing**: Decryption happens in memory only

## 🔧 Technical Implementation

### Frontend Components

#### Main Components
- `E2EEGroupSharing.tsx`: Main interface with authentication and group operations
- `E2EEDemo.tsx`: System test component for validation

#### Utilities
- `src/lib/api.ts`: HTTP client for Go backend communication
- `src/lib/encryption.ts`: Encryption utilities using Tauri APIs
- `src/hooks/useE2EESession.ts`: State management for user sessions

#### Types
- `src/types/e2ee.ts`: TypeScript definitions for all E2EE data structures

### Backend Structure

#### Go Modules
- `main.go`: HTTP server setup and routing
- `models/`: Data structures (User, Group, File)
- `handlers/`: HTTP request handlers
- `storage/`: In-memory storage implementation
- `utils/`: Response helpers and validation

#### API Endpoints
- `POST /register`: User registration with E2EE key bundles
- `POST /groups`: Create new groups
- `POST /groups/{groupId}/members`: Add members to groups
- `POST /groups/{groupId}/files`: Share encrypted files
- `GET /groups/{groupId}/files`: List group files
- `GET /health`: Health check

### Tauri Integration

#### New Commands Added
- `encrypt_data`: Encrypt data using AES-256-GCM
- `decrypt_data`: Decrypt data using AES-256-GCM

#### Encryption Flow
1. Frontend reads file as ArrayBuffer
2. Converts to base64 for Tauri command
3. Tauri encrypts using Rust encryption service
4. Returns encrypted data + metadata
5. Frontend sends encrypted data to Go backend

## 🧪 Testing

### Automated System Test
The `E2EEDemo` component provides comprehensive testing:

1. **Key Generation Test**: Validates E2EE key bundle creation
2. **Backend Connection Test**: Verifies Go server availability
3. **Encryption Test**: Tests file encryption/decryption cycle
4. **User Registration Test**: Tests backend user creation
5. **Group Creation Test**: Tests group management
6. **File Sharing Test**: Tests complete file sharing workflow
7. **File Listing Test**: Tests file retrieval

### Manual Testing
Use the main interface to:
1. Register a new user
2. Create groups
3. Add members (demo functionality)
4. Upload and encrypt files
5. View shared files

## 🔒 Security Considerations

### Current Implementation
- ✅ Client-side encryption before transmission
- ✅ E2EE key bundle generation
- ✅ AES-256-GCM encryption
- ✅ In-memory decryption only
- ✅ Proper key management

### Production Considerations
- 🔄 Add proper authentication tokens (JWT)
- 🔄 Implement key exchange protocols
- 🔄 Add rate limiting and input sanitization
- 🔄 Use bcrypt for password hashing
- 🔄 Add HTTPS/TLS encryption
- 🔄 Implement proper key rotation
- 🔄 Add audit logging

## 📁 File Structure

```
├── src-go/                     # Go backend
│   ├── main.go
│   ├── models/
│   ├── handlers/
│   ├── storage/
│   ├── middleware/
│   └── utils/
├── src/
│   ├── components/
│   │   ├── E2EEGroupSharing.tsx
│   │   └── E2EEDemo.tsx
│   ├── lib/
│   │   ├── api.ts
│   │   └── encryption.ts
│   ├── hooks/
│   │   └── useE2EESession.ts
│   └── types/
│       └── e2ee.ts
└── src-tauri/
    └── src/
        └── commands.rs         # Added encryption commands
```

## 🎯 Next Steps

### Immediate Improvements
1. Complete file download implementation
2. Add proper error handling and retry logic
3. Implement file integrity verification
4. Add progress indicators for large files

### Advanced Features
1. Real-time group messaging
2. File versioning and history
3. Advanced permission management
4. Mobile app support

### Production Readiness
1. Database persistence
2. Horizontal scaling
3. Key escrow and recovery
4. Compliance and auditing

## 🤝 Usage Examples

### Register and Create Group
```typescript
// Generate keys
const keyBundle = await generateKeyBundle();

// Register user
const result = await api.register('alice', 'password123', keyBundle);

// Create group
const group = await api.createGroup('My Team', result.user.id);
```

### Share Encrypted File
```typescript
// Read file
const fileData = await readFileAsArrayBuffer(file);

// Encrypt
const { encryptedData, metadata } = await encryptFile(fileData);

// Share
await api.shareFile(groupId, file, encryptedData, metadata, userId);
```

This integration provides a solid foundation for E2EE group file sharing with room for production enhancements.
