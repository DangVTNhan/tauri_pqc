package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"e2ee-backend/models"
	"e2ee-backend/storage"
	"e2ee-backend/utils"
)

// MessageHandler handles message queue operations
type MessageHandler struct {
	storage *storage.MemoryStorage
}

// NewMessageHandler creates a new message handler
func NewMessageHandler(storage *storage.MemoryStorage) *MessageHandler {
	return &MessageHandler{
		storage: storage,
	}
}

// SendWrappedKey sends a wrapped key to a user's message queue
func (h *MessageHandler) SendWrappedKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req models.WrappedKeyMessage
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteBadRequestResponse(w, "Invalid JSON payload")
		return
	}

	// Validate request
	if req.FileID == "" {
		utils.WriteBadRequestResponse(w, "File ID is required")
		return
	}

	if req.GroupID == "" {
		utils.WriteBadRequestResponse(w, "Group ID is required")
		return
	}

	if req.RecipientID == "" {
		utils.WriteBadRequestResponse(w, "Recipient ID is required")
		return
	}

	if req.WrappedKey.EncryptedKey == "" {
		utils.WriteBadRequestResponse(w, "Wrapped key is required")
		return
	}

	// Verify that the recipient exists
	_, err := h.storage.GetUser(req.RecipientID)
	if err != nil {
		utils.WriteBadRequestResponse(w, "Recipient user not found")
		return
	}

	// Verify that the file exists
	file, err := h.storage.GetFile(req.FileID)
	if err != nil {
		utils.WriteBadRequestResponse(w, "File not found")
		return
	}

	// Verify that the group exists and file belongs to it
	if file.GroupID != req.GroupID {
		utils.WriteBadRequestResponse(w, "File does not belong to the specified group")
		return
	}

	// Create wrapped message
	message := models.NewWrappedMessage(
		req.FileID,
		req.GroupID,
		"", // SenderID will be extracted from auth context in production
		req.RecipientID,
		req.WrappedKey,
	)

	// Send message to user's queue
	if err := h.storage.SendWrappedMessage(message); err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "Failed to send wrapped key")
		return
	}

	utils.WriteSuccessResponse(w, map[string]interface{}{
		"message_id":   message.ID,
		"recipient_id": message.RecipientID,
		"file_id":      message.FileID,
		"sent_at":      message.CreatedAt,
	})
}

// GetUserMessages retrieves all messages for a user
func (h *MessageHandler) GetUserMessages(w http.ResponseWriter, r *http.Request) {
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

	// Verify that the user exists
	_, err := h.storage.GetUser(userID)
	if err != nil {
		utils.WriteNotFoundResponse(w, "User not found")
		return
	}

	// Get user's messages
	messages, err := h.storage.GetUserMessages(userID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve messages")
		return
	}

	utils.WriteSuccessResponse(w, map[string]interface{}{
		"user_id":  userID,
		"messages": messages,
		"count":    len(messages),
	})
}

// GetUnprocessedMessages retrieves unprocessed messages for a user
func (h *MessageHandler) GetUnprocessedMessages(w http.ResponseWriter, r *http.Request) {
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

	// Verify that the user exists
	_, err := h.storage.GetUser(userID)
	if err != nil {
		utils.WriteNotFoundResponse(w, "User not found")
		return
	}

	// Get user's unprocessed messages
	messages, err := h.storage.GetUnprocessedMessages(userID)
	if err != nil {
		utils.WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve unprocessed messages")
		return
	}

	utils.WriteSuccessResponse(w, map[string]interface{}{
		"user_id":  userID,
		"messages": messages,
		"count":    len(messages),
	})
}

// MarkMessageProcessed marks a message as processed
func (h *MessageHandler) MarkMessageProcessed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract message ID from URL path
	messageID := h.extractMessageIDFromPath(r.URL.Path)
	if messageID == "" {
		utils.WriteBadRequestResponse(w, "Invalid message ID in URL")
		return
	}

	// Mark message as processed
	if err := h.storage.MarkMessageProcessed(messageID); err != nil {
		utils.WriteNotFoundResponse(w, "Message not found")
		return
	}

	utils.WriteSuccessResponse(w, map[string]interface{}{
		"message_id": messageID,
		"processed":  true,
	})
}

// extractUserIDFromPath extracts the user ID from URL paths like /users/{userId}/messages
func (h *MessageHandler) extractUserIDFromPath(path string) string {
	// Expected format: /users/{userId}/messages or /users/{userId}/messages/unprocessed
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "users" {
		return parts[1]
	}
	return ""
}

// extractMessageIDFromPath extracts the message ID from URL paths like /messages/{messageId}/processed
func (h *MessageHandler) extractMessageIDFromPath(path string) string {
	// Expected format: /messages/{messageId}/processed
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "messages" {
		return parts[1]
	}
	return ""
}

// SendBulkWrappedKeys sends wrapped keys to multiple users (for group file sharing)
func (h *MessageHandler) SendBulkWrappedKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		FileID      string                     `json:"file_id"`
		GroupID     string                     `json:"group_id"`
		WrappedKeys map[string]models.WrappedKey `json:"wrapped_keys"` // userID -> WrappedKey
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteBadRequestResponse(w, "Invalid JSON payload")
		return
	}

	// Validate request
	if req.FileID == "" {
		utils.WriteBadRequestResponse(w, "File ID is required")
		return
	}

	if req.GroupID == "" {
		utils.WriteBadRequestResponse(w, "Group ID is required")
		return
	}

	if len(req.WrappedKeys) == 0 {
		utils.WriteBadRequestResponse(w, "At least one wrapped key is required")
		return
	}

	// Verify that the file exists and belongs to the group
	file, err := h.storage.GetFile(req.FileID)
	if err != nil {
		utils.WriteBadRequestResponse(w, "File not found")
		return
	}

	if file.GroupID != req.GroupID {
		utils.WriteBadRequestResponse(w, "File does not belong to the specified group")
		return
	}

	// Send wrapped keys to all recipients
	var sentMessages []string
	var failedRecipients []string

	for recipientID, wrappedKey := range req.WrappedKeys {
		// Verify recipient exists
		_, err := h.storage.GetUser(recipientID)
		if err != nil {
			failedRecipients = append(failedRecipients, recipientID)
			continue
		}

		// Create and send message
		message := models.NewWrappedMessage(
			req.FileID,
			req.GroupID,
			"", // SenderID will be extracted from auth context in production
			recipientID,
			wrappedKey,
		)

		if err := h.storage.SendWrappedMessage(message); err != nil {
			failedRecipients = append(failedRecipients, recipientID)
			continue
		}

		sentMessages = append(sentMessages, message.ID)
	}

	utils.WriteSuccessResponse(w, map[string]interface{}{
		"file_id":            req.FileID,
		"group_id":           req.GroupID,
		"sent_messages":      sentMessages,
		"failed_recipients":  failedRecipients,
		"total_sent":         len(sentMessages),
		"total_failed":       len(failedRecipients),
	})
}
