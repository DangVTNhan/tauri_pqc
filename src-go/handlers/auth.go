package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"e2ee-backend/models"
	"e2ee-backend/storage"
	"e2ee-backend/utils"
)

// AuthHandler handles authentication-related requests
type AuthHandler struct {
	storage *storage.MemoryStorage
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(storage *storage.MemoryStorage) *AuthHandler {
	return &AuthHandler{
		storage: storage,
	}
}

// RegisterUser handles user registration
func (h *AuthHandler) RegisterUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req models.UserRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteBadRequestResponse(w, "Invalid JSON payload")
		return
	}

	// Validate input
	if err := utils.ValidateUsername(req.Username); err != nil {
		utils.WriteBadRequestResponse(w, err.Error())
		return
	}

	// Validate public key bundle
	if err := h.validatePublicKeyBundle(req.PublicKeyBundle); err != nil {
		utils.WriteBadRequestResponse(w, err.Error())
		return
	}

	// Check if username already exists
	if _, err := h.storage.GetUserByUsername(req.Username); err == nil {
		utils.WriteConflictResponse(w, "Username already exists")
		return
	}

	// Create new user (SECURITY: Only store public key bundle)
	user := models.NewUser(req.Username, req.PublicKeyBundle)

	// Store user
	if err := h.storage.CreateUser(user); err != nil {
		utils.WriteInternalErrorResponse(w, "Failed to create user")
		return
	}

	// Return success response with user wrapped in response object
	response := map[string]interface{}{
		"user": user.ToResponse(),
	}
	utils.WriteCreatedResponse(w, response)
}

// LoginUser handles user login
// SECURITY: No password verification - authentication is done client-side
func (h *AuthHandler) LoginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteBadRequestResponse(w, "Invalid JSON payload")
		return
	}

	// Validate input
	if err := utils.ValidateUsername(req.Username); err != nil {
		utils.WriteBadRequestResponse(w, err.Error())
		return
	}

	// Get user by username
	user, err := h.storage.GetUserByUsername(req.Username)
	if err != nil {
		utils.WriteNotFoundResponse(w, "User not found")
		return
	}

	// Get user's groups
	groups, err := h.storage.GetGroupsByUser(user.ID)
	if err != nil {
		// If we can't get groups, just return empty array
		groups = []*models.Group{}
	}

	// Return success response with user and groups
	response := map[string]interface{}{
		"user":   user.ToResponse(),
		"groups": groups,
	}
	utils.WriteSuccessResponse(w, response)
}

// GetUserByUsername handles requests to get a user by username
func (h *AuthHandler) GetUserByUsername(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract username from URL path
	username := h.extractUsernameFromPath(r.URL.Path)
	if username == "" {
		utils.WriteBadRequestResponse(w, "Invalid username in URL")
		return
	}

	// Get user by username
	user, err := h.storage.GetUserByUsername(username)
	if err != nil {
		utils.WriteNotFoundResponse(w, "User not found")
		return
	}

	// Return user response (without sensitive data)
	utils.WriteSuccessResponse(w, user.ToResponse())
}

// validatePublicKeyBundle validates the public key bundle
// SECURITY: Only validates public keys - never accepts private keys
func (h *AuthHandler) validatePublicKeyBundle(publicKeys models.PublicKeyBundle) error {
	// Validate public keys
	if len(publicKeys.IdentityKey) == 0 {
		return utils.NewValidationError("public identity key cannot be empty")
	}

	if len(publicKeys.SignedPreKey) == 0 {
		return utils.NewValidationError("public signed pre-key cannot be empty")
	}

	if len(publicKeys.KyberPreKey) == 0 {
		return utils.NewValidationError("public kyber pre-key cannot be empty")
	}

	if len(publicKeys.OneTimePreKeys) == 0 {
		return utils.NewValidationError("at least one public one-time pre-key is required")
	}

	if len(publicKeys.Signature) == 0 {
		return utils.NewValidationError("signature cannot be empty")
	}

	// Additional validation could include:
	// - Key length validation (Ed25519: 32 bytes, X25519: 32 bytes, Kyber-768: 1184 bytes)
	// - Signature verification
	// - Key format validation

	return nil
}

// GetPublicKeyBundle handles requests to get a user's public key bundle
func (h *AuthHandler) GetPublicKeyBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract user ID from URL path
	userID := h.extractUserIDFromPath(r.URL.Path)
	if userID == "" {
		utils.WriteBadRequestResponse(w, "Invalid user ID in URL")
		return
	}

	// Get user
	user, err := h.storage.GetUser(userID)
	if err != nil {
		utils.WriteNotFoundResponse(w, "User not found")
		return
	}

	// Return public key bundle
	utils.WriteSuccessResponse(w, user.ToPublicKeyBundleResponse())
}

// GetPublicKeyBundles handles requests to get multiple users' public key bundles
func (h *AuthHandler) GetPublicKeyBundles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		UserIDs []string `json:"user_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteBadRequestResponse(w, "Invalid JSON payload")
		return
	}

	if len(req.UserIDs) == 0 {
		utils.WriteBadRequestResponse(w, "user_ids is required")
		return
	}

	var bundles []models.PublicKeyBundleResponse
	for _, userID := range req.UserIDs {
		user, err := h.storage.GetUser(userID)
		if err != nil {
			// Skip users that don't exist
			continue
		}
		bundles = append(bundles, user.ToPublicKeyBundleResponse())
	}

	utils.WriteSuccessResponse(w, map[string]interface{}{
		"public_key_bundles": bundles,
	})
}

// extractUserIDFromPath extracts the user ID from URL paths like /users/{userId}/public-keys
func (h *AuthHandler) extractUserIDFromPath(path string) string {
	// Expected format: /users/{userId}/public-keys
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "users" {
		return parts[1]
	}
	return ""
}

// extractUsernameFromPath extracts the username from URL paths like /users/by-username/{username}
func (h *AuthHandler) extractUsernameFromPath(path string) string {
	// Expected format: /users/by-username/{username}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 3 && parts[0] == "users" && parts[1] == "by-username" {
		return parts[2]
	}
	return ""
}
