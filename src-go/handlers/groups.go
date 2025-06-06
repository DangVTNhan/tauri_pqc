package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"e2ee-backend/models"
	"e2ee-backend/storage"
	"e2ee-backend/utils"
)

// GroupHandler handles group-related requests
type GroupHandler struct {
	storage *storage.MemoryStorage
}

// NewGroupHandler creates a new group handler
func NewGroupHandler(storage *storage.MemoryStorage) *GroupHandler {
	return &GroupHandler{
		storage: storage,
	}
}

// CreateGroup handles group creation
func (h *GroupHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req models.GroupCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteBadRequestResponse(w, "Invalid JSON payload")
		return
	}

	// Validate input
	if err := utils.ValidateGroupName(req.Name); err != nil {
		utils.WriteBadRequestResponse(w, err.Error())
		return
	}

	if req.CreatorID == "" {
		utils.WriteBadRequestResponse(w, "creator_id is required")
		return
	}

	// Verify creator exists
	creator, err := h.storage.GetUser(req.CreatorID)
	if err != nil {
		utils.WriteNotFoundResponse(w, "Creator user not found")
		return
	}

	// Create new group
	group := models.NewGroup(req.Name, req.CreatorID)

	// Store group
	if err := h.storage.CreateGroup(group); err != nil {
		utils.WriteInternalErrorResponse(w, "Failed to create group")
		return
	}

	// Update creator's group memberships
	creator.AddGroupMembership(group.ID)
	if err := h.storage.UpdateUser(creator); err != nil {
		utils.WriteInternalErrorResponse(w, "Failed to update user memberships")
		return
	}

	// Return success response
	utils.WriteCreatedResponse(w, group.ToResponse())
}

// AddMember handles adding a member to a group
func (h *GroupHandler) AddMember(w http.ResponseWriter, r *http.Request) {
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

	var req models.GroupMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteBadRequestResponse(w, "Invalid JSON payload")
		return
	}

	if req.UserID == "" {
		utils.WriteBadRequestResponse(w, "user_id is required")
		return
	}

	// Get group
	group, err := h.storage.GetGroup(groupID)
	if err != nil {
		utils.WriteNotFoundResponse(w, "Group not found")
		return
	}

	// Verify user exists
	user, err := h.storage.GetUser(req.UserID)
	if err != nil {
		utils.WriteNotFoundResponse(w, "User not found")
		return
	}

	// Check if user is already a member
	if group.IsMember(req.UserID) {
		utils.WriteConflictResponse(w, "User is already a member of this group")
		return
	}

	// Add member to group
	group.AddMember(req.UserID)
	if err := h.storage.UpdateGroup(group); err != nil {
		utils.WriteInternalErrorResponse(w, "Failed to update group")
		return
	}

	// Update user's group memberships
	user.AddGroupMembership(groupID)
	if err := h.storage.UpdateUser(user); err != nil {
		utils.WriteInternalErrorResponse(w, "Failed to update user memberships")
		return
	}

	// Return success response
	utils.WriteSuccessResponse(w, map[string]interface{}{
		"message":  "User added to group successfully",
		"group_id": groupID,
		"user_id":  req.UserID,
	})
}

// AddWrappedKeysForNewMember handles adding wrapped master keys for a new group member
func (h *GroupHandler) AddWrappedKeysForNewMember(w http.ResponseWriter, r *http.Request) {
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

	var req struct {
		UserID      string                       `json:"user_id"`
		WrappedKeys map[string]models.WrappedKey `json:"wrapped_keys"` // fileID -> wrapped key
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteBadRequestResponse(w, "Invalid JSON payload")
		return
	}

	if req.UserID == "" {
		utils.WriteBadRequestResponse(w, "user_id is required")
		return
	}

	// Get group
	group, err := h.storage.GetGroup(groupID)
	if err != nil {
		utils.WriteNotFoundResponse(w, "Group not found")
		return
	}

	// Verify user is a member of the group
	if !group.IsMember(req.UserID) {
		utils.WriteForbiddenResponse(w, "User is not a member of this group")
		return
	}

	// Send wrapped keys to the new member via message queue
	for fileID, wrappedKey := range req.WrappedKeys {
		file, err := h.storage.GetFile(fileID)
		if err != nil {
			continue // Skip files that don't exist
		}

		// Verify file belongs to this group
		if file.GroupID != groupID {
			continue // Skip files not in this group
		}

		// Create wrapped message for the new member
		message := models.NewWrappedMessage(
			fileID,
			groupID,
			"", // SenderID will be extracted from auth context in production
			req.UserID,
			wrappedKey,
		)

		// Send message to user's queue
		if err := h.storage.SendWrappedMessage(message); err != nil {
			utils.WriteInternalErrorResponse(w, "Failed to send wrapped key")
			return
		}
	}

	// Return success response
	utils.WriteSuccessResponse(w, map[string]interface{}{
		"message":     "Wrapped keys added successfully",
		"group_id":    groupID,
		"user_id":     req.UserID,
		"files_count": len(req.WrappedKeys),
	})
}

// GetGroup handles retrieving a single group by ID
func (h *GroupHandler) GetGroup(w http.ResponseWriter, r *http.Request) {
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

	// Get group
	group, err := h.storage.GetGroup(groupID)
	if err != nil {
		utils.WriteNotFoundResponse(w, "Group not found")
		return
	}

	// Return group information
	utils.WriteSuccessResponse(w, group.ToResponse())
}

// extractGroupIDFromPath extracts the group ID from URL paths like /groups/{groupId}/members
func (h *GroupHandler) extractGroupIDFromPath(path string) string {
	// Expected format: /groups/{groupId}/members, /groups/{groupId}/files, or /groups/{groupId}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "groups" {
		return parts[1]
	}
	return ""
}
