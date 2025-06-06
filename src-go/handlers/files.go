package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"e2ee-backend/models"
	"e2ee-backend/storage"
	"e2ee-backend/utils"
)

// FileHandler handles file-related requests
type FileHandler struct {
	storage *storage.MemoryStorage
}

// NewFileHandler creates a new file handler
func NewFileHandler(storage *storage.MemoryStorage) *FileHandler {
	return &FileHandler{
		storage: storage,
	}
}

// ShareFile handles file sharing within a group
func (h *FileHandler) ShareFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract group ID from URL path
	groupID := h.extractGroupIDFromPath(r.URL.Path)
	if groupID == "" {
		utils.WriteBadRequestResponse(w, "Invalid group ID in URL")
		return
	}

	var req models.FileShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteBadRequestResponse(w, "Invalid JSON payload")
		return
	}

	// Validate input
	if err := h.validateFileShareRequest(req); err != nil {
		utils.WriteBadRequestResponse(w, err.Error())
		return
	}

	// Get group
	group, err := h.storage.GetGroup(groupID)
	if err != nil {
		utils.WriteNotFoundResponse(w, "Group not found")
		return
	}

	// Verify user exists and is a member of the group
	_, err = h.storage.GetUser(req.SharedBy)
	if err != nil {
		utils.WriteNotFoundResponse(w, "User not found")
		return
	}

	if !group.IsMember(req.SharedBy) {
		utils.WriteForbiddenResponse(w, "User is not a member of this group")
		return
	}

	// Check file size against group settings
	if err := utils.ValidateFileSize(req.Size, group.Settings.MaxFileSize); err != nil {
		utils.WriteBadRequestResponse(w, err.Error())
		return
	}

	// Create new shared file
	file := models.NewSharedFile(req, groupID)

	// Store file
	if err := h.storage.CreateFile(file); err != nil {
		utils.WriteInternalErrorResponse(w, "Failed to store file")
		return
	}

	// Add file to group
	group.AddSharedFile(file.ID)
	if err := h.storage.UpdateGroup(group); err != nil {
		utils.WriteInternalErrorResponse(w, "Failed to update group")
		return
	}

	// Return success response
	utils.WriteCreatedResponse(w, file.ToResponse())
}

// GetGroupFiles handles retrieving files for a group
func (h *FileHandler) GetGroupFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract group ID from URL path
	groupID := h.extractGroupIDFromPath(r.URL.Path)
	if groupID == "" {
		utils.WriteBadRequestResponse(w, "Invalid group ID in URL")
		return
	}

	// Get group to verify it exists
	_, err := h.storage.GetGroup(groupID)
	if err != nil {
		utils.WriteNotFoundResponse(w, "Group not found")
		return
	}

	// Get files for the group
	files, err := h.storage.GetFilesByGroup(groupID)
	if err != nil {
		utils.WriteInternalErrorResponse(w, "Failed to retrieve files")
		return
	}

	// Convert to response format
	var fileResponses []models.FileResponse
	for _, file := range files {
		fileResponses = append(fileResponses, file.ToResponse())
	}

	// Ensure we always return an array, even if empty
	if fileResponses == nil {
		fileResponses = make([]models.FileResponse, 0)
	}

	// Return success response
	utils.WriteSuccessResponse(w, map[string]interface{}{
		"group_id": groupID,
		"files":    fileResponses,
	})
}

// GetFileInfo handles retrieving file metadata (zero-knowledge - no content or keys)
func (h *FileHandler) GetFileInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract file ID from URL path
	fileID := h.extractFileIDFromPath(r.URL.Path)
	if fileID == "" {
		utils.WriteBadRequestResponse(w, "Invalid file ID in URL")
		return
	}

	// Get user ID from query parameter
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		utils.WriteBadRequestResponse(w, "user_id query parameter is required")
		return
	}

	// Get file
	file, err := h.storage.GetFile(fileID)
	if err != nil {
		utils.WriteNotFoundResponse(w, "File not found")
		return
	}

	// Get group to verify user membership
	group, err := h.storage.GetGroup(file.GroupID)
	if err != nil {
		utils.WriteNotFoundResponse(w, "Group not found")
		return
	}

	// Verify user is a member of the group
	if !group.IsMember(userID) {
		utils.WriteForbiddenResponse(w, "User is not a member of this group")
		return
	}

	// Mark as downloaded by this user
	file.MarkDownloadedBy(userID)
	h.storage.UpdateFile(file)

	// Return file metadata only (zero-knowledge: no encryption keys or content)
	utils.WriteSuccessResponse(w, map[string]interface{}{
		"file_id":       file.ID,
		"blob_url":      file.BlobURL,
		"blob_hash":     file.BlobHash,
		"original_name": file.OriginalName,
		"mime_type":     file.MimeType,
		"size":          file.Size,
		"shared_by":     file.SharedBy,
		"shared_at":     file.SharedAt,
		"group_id":      file.GroupID,
	})
}

// validateFileShareRequest validates the file share request
func (h *FileHandler) validateFileShareRequest(req models.FileShareRequest) error {
	if err := utils.ValidateFileName(req.OriginalName); err != nil {
		return err
	}

	if req.Size <= 0 {
		return utils.NewValidationError("file size must be greater than 0")
	}

	if req.SharedBy == "" {
		return utils.NewValidationError("shared_by is required")
	}

	if req.MimeType == "" {
		return utils.NewValidationError("mime_type is required")
	}

	// Validate blob URL and hash (zero-knowledge architecture)
	if req.BlobURL == "" {
		return utils.NewValidationError("blob_url is required")
	}

	if req.BlobHash == "" {
		return utils.NewValidationError("blob_hash is required")
	}

	return nil
}

// extractGroupIDFromPath extracts the group ID from URL paths like /groups/{groupId}/files
func (h *FileHandler) extractGroupIDFromPath(path string) string {
	// Expected format: /groups/{groupId}/files
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "groups" {
		return parts[1]
	}
	return ""
}

// extractFileIDFromPath extracts the file ID from URL paths like /files/{fileId}/content
func (h *FileHandler) extractFileIDFromPath(path string) string {
	// Expected format: /files/{fileId}/content
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "files" {
		return parts[1]
	}
	return ""
}
