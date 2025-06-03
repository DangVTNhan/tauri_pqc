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

	if err := utils.ValidatePassword(req.Password); err != nil {
		utils.WriteBadRequestResponse(w, err.Error())
		return
	}

	// Validate key bundle
	if err := h.validateKeyBundle(req.KeyBundle); err != nil {
		utils.WriteBadRequestResponse(w, err.Error())
		return
	}

	// Check if username already exists
	if _, err := h.storage.GetUserByUsername(req.Username); err == nil {
		utils.WriteConflictResponse(w, "Username already exists")
		return
	}

	// Hash password
	passwordHash := utils.HashPassword(req.Password)

	// Create new user
	user := models.NewUser(req.Username, passwordHash, req.KeyBundle)

	// Store user
	if err := h.storage.CreateUser(user); err != nil {
		utils.WriteInternalErrorResponse(w, "Failed to create user")
		return
	}

	// Return success response
	utils.WriteCreatedResponse(w, user.ToResponse())
}

// validateKeyBundle validates the E2EE key bundle
func (h *AuthHandler) validateKeyBundle(keyBundle models.KeyBundle) error {
	// Validate public keys
	if len(keyBundle.PublicKeys.IdentityKey) == 0 {
		return utils.NewValidationError("public identity key cannot be empty")
	}

	if len(keyBundle.PublicKeys.SignedPreKey) == 0 {
		return utils.NewValidationError("public signed pre-key cannot be empty")
	}

	if len(keyBundle.PublicKeys.KyberPreKey) == 0 {
		return utils.NewValidationError("public kyber pre-key cannot be empty")
	}

	if len(keyBundle.PublicKeys.OneTimePreKeys) == 0 {
		return utils.NewValidationError("at least one public one-time pre-key is required")
	}

	if len(keyBundle.PublicKeys.Signature) == 0 {
		return utils.NewValidationError("signature cannot be empty")
	}

	// Validate private keys
	if len(keyBundle.PrivateKeys.IdentityKey) == 0 {
		return utils.NewValidationError("private identity key cannot be empty")
	}

	if len(keyBundle.PrivateKeys.SignedPreKey) == 0 {
		return utils.NewValidationError("private signed pre-key cannot be empty")
	}

	if len(keyBundle.PrivateKeys.KyberPreKey) == 0 {
		return utils.NewValidationError("private kyber pre-key cannot be empty")
	}

	if len(keyBundle.PrivateKeys.OneTimePreKeys) == 0 {
		return utils.NewValidationError("at least one private one-time pre-key is required")
	}

	if len(keyBundle.PrivateKeys.Salt) == 0 {
		return utils.NewValidationError("salt cannot be empty")
	}

	// Validate individual nonces for each private key
	if len(keyBundle.PrivateKeys.IdentityKeyNonce) == 0 {
		return utils.NewValidationError("identity key nonce cannot be empty")
	}

	if len(keyBundle.PrivateKeys.SignedPreKeyNonce) == 0 {
		return utils.NewValidationError("signed pre-key nonce cannot be empty")
	}

	if len(keyBundle.PrivateKeys.KyberPreKeyNonce) == 0 {
		return utils.NewValidationError("kyber pre-key nonce cannot be empty")
	}

	if len(keyBundle.PrivateKeys.OneTimePreKeysNonces) == 0 {
		return utils.NewValidationError("at least one one-time pre-key nonce is required")
	}

	// Additional validation could include:
	// - Key length validation
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
