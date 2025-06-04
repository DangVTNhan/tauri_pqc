package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// ValidateUsername checks if a username is valid
func ValidateUsername(username string) error {
	if len(username) < 3 {
		return NewValidationError("username must be at least 3 characters long")
	}
	if len(username) > 50 {
		return NewValidationError("username must be no more than 50 characters long")
	}

	// Allow alphanumeric characters, underscores, and hyphens
	matched, _ := regexp.MatchString("^[a-zA-Z0-9_-]+$", username)
	if !matched {
		return NewValidationError("username can only contain letters, numbers, underscores, and hyphens")
	}

	return nil
}

// ValidatePassword checks if a password meets security requirements
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return NewValidationError("password must be at least 8 characters long")
	}
	if len(password) > 128 {
		return NewValidationError("password must be no more than 128 characters long")
	}

	// Check for at least one uppercase letter
	hasUpper, _ := regexp.MatchString("[A-Z]", password)
	if !hasUpper {
		return NewValidationError("password must contain at least one uppercase letter")
	}

	// Check for at least one lowercase letter
	hasLower, _ := regexp.MatchString("[a-z]", password)
	if !hasLower {
		return NewValidationError("password must contain at least one lowercase letter")
	}

	// Check for at least one digit
	hasDigit, _ := regexp.MatchString("[0-9]", password)
	if !hasDigit {
		return NewValidationError("password must contain at least one digit")
	}

	return nil
}

// ValidateGroupName checks if a group name is valid
func ValidateGroupName(name string) error {
	name = strings.TrimSpace(name)
	if len(name) < 1 {
		return NewValidationError("group name cannot be empty")
	}
	if len(name) > 100 {
		return NewValidationError("group name must be no more than 100 characters long")
	}

	return nil
}

// ValidateFileName checks if a file name is valid
func ValidateFileName(name string) error {
	name = strings.TrimSpace(name)
	if len(name) < 1 {
		return NewValidationError("file name cannot be empty")
	}
	if len(name) > 255 {
		return NewValidationError("file name must be no more than 255 characters long")
	}

	// Check for invalid characters
	invalidChars := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|"}
	for _, char := range invalidChars {
		if strings.Contains(name, char) {
			return NewValidationError("file name contains invalid characters")
		}
	}

	return nil
}

// ValidateFileSize checks if a file size is within acceptable limits
func ValidateFileSize(size int64, maxSize int64) error {
	if size <= 0 {
		return NewValidationError("file size must be greater than 0")
	}
	if size > maxSize {
		return NewValidationError("file size exceeds maximum allowed size")
	}

	return nil
}

// HashPassword creates a SHA-256 hash of the password
// Note: In production, use bcrypt or similar instead of SHA-256
func HashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// VerifyPassword checks if a password matches the hash
func VerifyPassword(password, hash string) bool {
	return HashPassword(password) == hash
}

// ValidationError represents a validation error
type ValidationError struct {
	Message string
}

func (e ValidationError) Error() string {
	return e.Message
}

// NewValidationError creates a new validation error
func NewValidationError(message string) ValidationError {
	return ValidationError{Message: message}
}

// IsValidationError checks if an error is a validation error
func IsValidationError(err error) bool {
	_, ok := err.(ValidationError)
	return ok
}

// GenerateID creates a random ID string
func GenerateID() string {
	bytes := make([]byte, 16) // 128-bit ID
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
