package models

import (
	"encoding/base64"
	"time"
)

// SharedFile represents a file shared within a group
type SharedFile struct {
	ID                 string                 `json:"id"`
	OriginalName       string                 `json:"original_name"`
	EncryptedName      string                 `json:"encrypted_name"`
	Size               int64                  `json:"size"`
	MimeType           string                 `json:"mime_type"`
	SharedBy           string                 `json:"shared_by"`
	SharedAt           time.Time              `json:"shared_at"`
	GroupID            string                 `json:"group_id"`
	EncryptedContent   []byte                 `json:"encrypted_content"`   // AES-256-GCM encrypted file content
	WrappedMasterKeys  map[string]WrappedKey  `json:"wrapped_master_keys"` // userID -> wrapped master key
	EncryptionMetadata FileEncryptionMetadata `json:"encryption_metadata"`
	DownloadedBy       []string               `json:"downloaded_by"`
	Status             FileStatus             `json:"status"`
	Description        string                 `json:"description,omitempty"`
}

// WrappedKey represents a master key wrapped (encrypted) for a specific user
type WrappedKey struct {
	EncryptedKey []byte `json:"encrypted_key"` // Master key encrypted with derived shared secret
	KeyExchange  KeyExchangeData `json:"key_exchange"`  // Key exchange data used for this wrapping
}

// KeyExchangeData contains the ephemeral keys and data needed for key exchange
type KeyExchangeData struct {
	EphemeralPublicKey []byte `json:"ephemeral_public_key"` // X25519 ephemeral public key
	KyberCiphertext    []byte `json:"kyber_ciphertext"`     // Kyber-768 ciphertext
	Salt               []byte `json:"salt"`                 // Salt for KDF
	Nonce              []byte `json:"nonce"`                // Nonce for key wrapping
}

// FileEncryptionMetadata contains encryption information for the file
type FileEncryptionMetadata struct {
	EncryptionKey      []byte `json:"encryption_key"`
	IV                 []byte `json:"iv"`
	AuthTag            []byte `json:"auth_tag"`
	ChunkSize          int32  `json:"chunk_size"`
	TotalChunks        int32  `json:"total_chunks"`
	Algorithm          string `json:"algorithm"`
	OriginalChecksum   []byte `json:"original_checksum"`
	ChecksumAlgorithm  string `json:"checksum_algorithm"`
}

// FileStatus represents the current status of a file
type FileStatus string

const (
	FileStatusAvailable    FileStatus = "available"
	FileStatusUploading    FileStatus = "uploading"
	FileStatusUploadFailed FileStatus = "upload_failed"
	FileStatusDeleted      FileStatus = "deleted"
	FileStatusExpired      FileStatus = "expired"
	FileStatusCorrupted    FileStatus = "corrupted"
)

// FileShareRequest represents the request to share a file
type FileShareRequest struct {
	OriginalName       string                 `json:"original_name"`
	Size               int64                  `json:"size"`
	MimeType           string                 `json:"mime_type"`
	SharedBy           string                 `json:"shared_by"`
	EncryptedContent   string                 `json:"encrypted_content"`   // File encrypted with master key (base64)
	WrappedMasterKeys  map[string]WrappedKey  `json:"wrapped_master_keys"` // Master key wrapped for each group member
	EncryptionMetadata FileEncryptionMetadata `json:"encryption_metadata"`
	Description        string                 `json:"description,omitempty"`
}

// FileResponse represents the response after file operations
type FileResponse struct {
	ID           string    `json:"id"`
	OriginalName string    `json:"original_name"`
	Size         int64     `json:"size"`
	MimeType     string    `json:"mime_type"`
	SharedBy     string    `json:"shared_by"`
	SharedAt     time.Time `json:"shared_at"`
	GroupID      string    `json:"group_id"`
	Status       FileStatus `json:"status"`
	Description  string    `json:"description,omitempty"`
}

// NewSharedFile creates a new shared file
func NewSharedFile(req FileShareRequest, groupID string) *SharedFile {
	// Decode base64 encrypted content to bytes
	encryptedContent, err := base64.StdEncoding.DecodeString(req.EncryptedContent)
	if err != nil {
		// If decoding fails, store as empty bytes (validation should catch this)
		encryptedContent = []byte{}
	}

	return &SharedFile{
		ID:                 generateID(),
		OriginalName:       req.OriginalName,
		EncryptedName:      "encrypted_" + generateID(),
		Size:               req.Size,
		MimeType:           req.MimeType,
		SharedBy:           req.SharedBy,
		SharedAt:           time.Now().UTC(),
		GroupID:            groupID,
		EncryptedContent:   encryptedContent,
		WrappedMasterKeys:  req.WrappedMasterKeys,
		EncryptionMetadata: req.EncryptionMetadata,
		DownloadedBy:       make([]string, 0),
		Status:             FileStatusAvailable,
		Description:        req.Description,
	}
}

// MarkDownloadedBy adds a user to the downloaded list
func (f *SharedFile) MarkDownloadedBy(userID string) {
	// Check if user already downloaded
	for _, id := range f.DownloadedBy {
		if id == userID {
			return
		}
	}
	f.DownloadedBy = append(f.DownloadedBy, userID)
}

// IsDownloadedBy checks if a user has downloaded this file
func (f *SharedFile) IsDownloadedBy(userID string) bool {
	for _, id := range f.DownloadedBy {
		if id == userID {
			return true
		}
	}
	return false
}

// IsAvailable checks if the file is available for download
func (f *SharedFile) IsAvailable() bool {
	return f.Status == FileStatusAvailable
}

// AddWrappedMasterKey adds a wrapped master key for a new group member
func (f *SharedFile) AddWrappedMasterKey(userID string, wrappedKey WrappedKey) {
	if f.WrappedMasterKeys == nil {
		f.WrappedMasterKeys = make(map[string]WrappedKey)
	}
	f.WrappedMasterKeys[userID] = wrappedKey
}

// GetWrappedMasterKey retrieves the wrapped master key for a specific user
func (f *SharedFile) GetWrappedMasterKey(userID string) (WrappedKey, bool) {
	wrappedKey, exists := f.WrappedMasterKeys[userID]
	return wrappedKey, exists
}

// RemoveWrappedMasterKey removes the wrapped master key for a user (when they leave the group)
func (f *SharedFile) RemoveWrappedMasterKey(userID string) {
	if f.WrappedMasterKeys != nil {
		delete(f.WrappedMasterKeys, userID)
	}
}

// ToResponse converts the file to a response object
func (f *SharedFile) ToResponse() FileResponse {
	return FileResponse{
		ID:           f.ID,
		OriginalName: f.OriginalName,
		Size:         f.Size,
		MimeType:     f.MimeType,
		SharedBy:     f.SharedBy,
		SharedAt:     f.SharedAt,
		GroupID:      f.GroupID,
		Status:       f.Status,
		Description:  f.Description,
	}
}
