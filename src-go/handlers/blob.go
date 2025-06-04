package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"e2ee-backend/models"
	"e2ee-backend/utils"
)

// BlobHandler handles blob storage operations
type BlobHandler struct {
	blobDir string // Directory to store encrypted blobs
}

// NewBlobHandler creates a new blob handler
func NewBlobHandler(blobDir string) *BlobHandler {
	// Create blob directory if it doesn't exist
	if err := os.MkdirAll(blobDir, 0755); err != nil {
		panic(fmt.Sprintf("Failed to create blob directory: %v", err))
	}

	return &BlobHandler{
		blobDir: blobDir,
	}
}

// UploadBlob handles encrypted file upload to blob storage
func (h *BlobHandler) UploadBlob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req models.BlobUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteBadRequestResponse(w, "Invalid JSON payload")
		return
	}

	// Validate request
	if req.EncryptedContent == "" {
		utils.WriteBadRequestResponse(w, "Encrypted content is required")
		return
	}

	if req.BlobHash == "" {
		utils.WriteBadRequestResponse(w, "Blob hash is required")
		return
	}

	// Decode base64 content
	encryptedData, err := base64.StdEncoding.DecodeString(req.EncryptedContent)
	if err != nil {
		utils.WriteBadRequestResponse(w, "Invalid base64 encrypted content")
		return
	}

	// Verify hash
	actualHash := sha256.Sum256(encryptedData)
	actualHashHex := hex.EncodeToString(actualHash[:])

	if actualHashHex != req.BlobHash {
		utils.WriteBadRequestResponse(w, "Hash verification failed")
		return
	}

	// Generate unique blob ID
	blobID := utils.GenerateID()
	blobPath := filepath.Join(h.blobDir, blobID+".blob")

	// Write encrypted data to file
	if err := os.WriteFile(blobPath, encryptedData, 0644); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "Failed to store blob")
		return
	}

	// Generate blob URL (in production, this would be an S3 URL or similar)
	blobURL := fmt.Sprintf("/blobs/%s", blobID)

	response := map[string]interface{}{
		"blob_id":   blobID,
		"blob_url":  blobURL,
		"blob_hash": req.BlobHash,
		"size":      len(encryptedData),
	}

	utils.WriteSuccessResponse(w, response)
}

// DownloadBlob handles encrypted file download from blob storage
func (h *BlobHandler) DownloadBlob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract blob ID from URL path
	blobID := h.extractBlobIDFromPath(r.URL.Path)
	if blobID == "" {
		utils.WriteBadRequestResponse(w, "Invalid blob ID in URL")
		return
	}

	blobPath := filepath.Join(h.blobDir, blobID+".blob")

	// Check if blob exists
	if _, err := os.Stat(blobPath); os.IsNotExist(err) {
		utils.WriteNotFoundResponse(w, "Blob not found")
		return
	}

	// Read encrypted blob
	encryptedData, err := os.ReadFile(blobPath)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "Failed to read blob")
		return
	}

	// Calculate hash for integrity check
	hash := sha256.Sum256(encryptedData)
	hashHex := hex.EncodeToString(hash[:])

	// Encode to base64 for JSON response
	base64Data := base64.StdEncoding.EncodeToString(encryptedData)

	response := map[string]interface{}{
		"blob_id":           blobID,
		"encrypted_content": base64Data,
		"blob_hash":         hashHex,
		"size":              len(encryptedData),
	}

	utils.WriteSuccessResponse(w, response)
}

// extractBlobIDFromPath extracts the blob ID from URL paths like /blobs/{blobId}
func (h *BlobHandler) extractBlobIDFromPath(path string) string {
	// Expected format: /blobs/{blobId}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "blobs" {
		return parts[1]
	}
	return ""
}

// GetBlobInfo returns information about a blob without downloading it
func (h *BlobHandler) GetBlobInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodHead {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract blob ID from URL path
	blobID := h.extractBlobIDFromPath(r.URL.Path)
	if blobID == "" {
		utils.WriteBadRequestResponse(w, "Invalid blob ID in URL")
		return
	}

	blobPath := filepath.Join(h.blobDir, blobID+".blob")

	// Check if blob exists and get info
	info, err := os.Stat(blobPath)
	if os.IsNotExist(err) {
		utils.WriteNotFoundResponse(w, "Blob not found")
		return
	}
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "Failed to get blob info")
		return
	}

	// Set headers with blob information
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	w.Header().Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
	w.WriteHeader(http.StatusOK)
}

// DeleteBlob removes a blob from storage (for cleanup)
func (h *BlobHandler) DeleteBlob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract blob ID from URL path
	blobID := h.extractBlobIDFromPath(r.URL.Path)
	if blobID == "" {
		utils.WriteBadRequestResponse(w, "Invalid blob ID in URL")
		return
	}

	blobPath := filepath.Join(h.blobDir, blobID+".blob")

	// Delete the blob file
	if err := os.Remove(blobPath); err != nil {
		if os.IsNotExist(err) {
			utils.WriteNotFoundResponse(w, "Blob not found")
			return
		}
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "Failed to delete blob")
		return
	}

	utils.WriteSuccessResponse(w, map[string]interface{}{
		"blob_id": blobID,
		"deleted": true,
	})
}

// ListBlobs returns a list of all blobs (for debugging/admin purposes)
func (h *BlobHandler) ListBlobs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	entries, err := os.ReadDir(h.blobDir)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "Failed to list blobs")
		return
	}

	var blobs []map[string]interface{}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".blob") {
			info, err := entry.Info()
			if err != nil {
				continue
			}

			blobID := strings.TrimSuffix(entry.Name(), ".blob")
			blobs = append(blobs, map[string]interface{}{
				"blob_id":     blobID,
				"size":        info.Size(),
				"modified_at": info.ModTime().UTC().Format(http.TimeFormat),
			})
		}
	}

	utils.WriteSuccessResponse(w, map[string]interface{}{
		"blobs": blobs,
		"count": len(blobs),
	})
}
