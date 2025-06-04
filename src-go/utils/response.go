package utils

import (
	"encoding/json"
	"net/http"
)

// APIResponse represents a standard API response
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Message string      `json:"message,omitempty"`
}

// WriteJSONResponse writes a JSON response with the given status code
func WriteJSONResponse(w http.ResponseWriter, statusCode int, response APIResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// WriteSuccessResponse writes a successful JSON response
func WriteSuccessResponse(w http.ResponseWriter, data interface{}) {
	WriteJSONResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    data,
	})
}

// WriteCreatedResponse writes a successful creation JSON response
func WriteCreatedResponse(w http.ResponseWriter, data interface{}) {
	WriteJSONResponse(w, http.StatusCreated, APIResponse{
		Success: true,
		Data:    data,
	})
}

// WriteErrorResponse writes an error JSON response
func WriteErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	WriteJSONResponse(w, statusCode, APIResponse{
		Success: false,
		Error:   message,
	})
}

// WriteBadRequestResponse writes a 400 Bad Request response
func WriteBadRequestResponse(w http.ResponseWriter, message string) {
	WriteErrorResponse(w, http.StatusBadRequest, message)
}

// WriteNotFoundResponse writes a 404 Not Found response
func WriteNotFoundResponse(w http.ResponseWriter, message string) {
	WriteErrorResponse(w, http.StatusNotFound, message)
}

// WriteInternalErrorResponse writes a 500 Internal Server Error response
func WriteInternalErrorResponse(w http.ResponseWriter, message string) {
	WriteErrorResponse(w, http.StatusInternalServerError, message)
}

// WriteUnauthorizedResponse writes a 401 Unauthorized response
func WriteUnauthorizedResponse(w http.ResponseWriter, message string) {
	WriteErrorResponse(w, http.StatusUnauthorized, message)
}

// WriteForbiddenResponse writes a 403 Forbidden response
func WriteForbiddenResponse(w http.ResponseWriter, message string) {
	WriteErrorResponse(w, http.StatusForbidden, message)
}

// WriteConflictResponse writes a 409 Conflict response
func WriteConflictResponse(w http.ResponseWriter, message string) {
	WriteErrorResponse(w, http.StatusConflict, message)
}
