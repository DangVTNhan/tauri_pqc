package models

import (
	"time"
)

// SharedFile represents a file shared within a group (zero-knowledge architecture)
type SharedFile struct {
	ID           string     `json:"id"`
	OriginalName string     `json:"original_name"`
	Size         int64      `json:"size"`
	MimeType     string     `json:"mime_type"`
	SharedBy     string     `json:"shared_by"`
	SharedAt     time.Time  `json:"shared_at"`
	GroupID      string     `json:"group_id"`
	Status       FileStatus `json:"status"`
	Description  string     `json:"description,omitempty"`
	// Zero-knowledge: only store blob URL, never encryption keys or content
	BlobURL      string   `json:"blob_url"`  // URL to encrypted file in blob storage
	BlobHash     string   `json:"blob_hash"` // Hash of encrypted blob for integrity
	DownloadedBy []string `json:"downloaded_by,omitempty"`
}

// WrappedKey represents a master key wrapped (encrypted) for a specific user
type WrappedKey struct {
	EncryptedKey string          `json:"encrypted_key"` // Master key encrypted with derived shared secret (base64)
	KeyExchange  KeyExchangeData `json:"key_exchange"`  // Key exchange data used for this wrapping
}

// KeyExchangeData contains the ephemeral keys and data needed for key exchange
type KeyExchangeData struct {
	EphemeralPublicKey string `json:"ephemeral_public_key"` // X25519 ephemeral public key (base64)
	KyberCiphertext    string `json:"kyber_ciphertext"`     // Kyber-768 ciphertext (base64)
	Salt               string `json:"salt"`                 // Salt for KDF (base64)
	Nonce              string `json:"nonce"`                // Nonce for key wrapping (base64)
}

// WrappedMessage represents a message in a user's inbox containing wrapped keys
type WrappedMessage struct {
	ID          string     `json:"id"`
	RecipientID string     `json:"recipient_id"`
	SenderID    string     `json:"sender_id"`
	FileID      string     `json:"file_id"`
	GroupID     string     `json:"group_id"`
	WrappedKey  WrappedKey `json:"wrapped_key"`
	CreatedAt   time.Time  `json:"created_at"`
	Processed   bool       `json:"processed"`
}

// MessageQueue represents a user's inbox for receiving wrapped keys
type MessageQueue struct {
	UserID   string            `json:"user_id"`
	Messages []*WrappedMessage `json:"messages"`
}

// BlobUploadRequest represents a request to upload encrypted file to blob storage
type BlobUploadRequest struct {
	EncryptedContent string `json:"encrypted_content"` // base64 encoded encrypted file
	BlobHash         string `json:"blob_hash"`         // SHA-256 hash of encrypted content
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

// FileShareRequest represents the request to share a file (zero-knowledge)
type FileShareRequest struct {
	OriginalName string `json:"original_name"`
	Size         int64  `json:"size"`
	MimeType     string `json:"mime_type"`
	SharedBy     string `json:"shared_by"`
	BlobURL      string `json:"blob_url"`  // URL to encrypted file in blob storage
	BlobHash     string `json:"blob_hash"` // Hash of encrypted blob for integrity
	Description  string `json:"description,omitempty"`
}

// WrappedKeyMessage represents a message to send wrapped keys to group members
type WrappedKeyMessage struct {
	FileID      string     `json:"file_id"`
	GroupID     string     `json:"group_id"`
	RecipientID string     `json:"recipient_id"`
	WrappedKey  WrappedKey `json:"wrapped_key"`
}

// FileResponse represents the response after file operations
type FileResponse struct {
	ID           string     `json:"id"`
	OriginalName string     `json:"original_name"`
	Size         int64      `json:"size"`
	MimeType     string     `json:"mime_type"`
	SharedBy     string     `json:"shared_by"`
	SharedAt     time.Time  `json:"shared_at"`
	GroupID      string     `json:"group_id"`
	Status       FileStatus `json:"status"`
	Description  string     `json:"description,omitempty"`
}

// NewSharedFile creates a new shared file (zero-knowledge)
func NewSharedFile(req FileShareRequest, groupID string) *SharedFile {
	return &SharedFile{
		ID:           generateID(),
		OriginalName: req.OriginalName,
		Size:         req.Size,
		MimeType:     req.MimeType,
		SharedBy:     req.SharedBy,
		SharedAt:     time.Now().UTC(),
		GroupID:      groupID,
		BlobURL:      req.BlobURL,
		BlobHash:     req.BlobHash,
		DownloadedBy: make([]string, 0),
		Status:       FileStatusAvailable,
		Description:  req.Description,
	}
}

// NewWrappedMessage creates a new wrapped message for the message queue
func NewWrappedMessage(fileID, groupID, senderID, recipientID string, wrappedKey WrappedKey) *WrappedMessage {
	return &WrappedMessage{
		ID:          generateID(),
		RecipientID: recipientID,
		SenderID:    senderID,
		FileID:      fileID,
		GroupID:     groupID,
		WrappedKey:  wrappedKey,
		CreatedAt:   time.Now().UTC(),
		Processed:   false,
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

// MarkProcessed marks a wrapped message as processed
func (m *WrappedMessage) MarkProcessed() {
	m.Processed = true
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
