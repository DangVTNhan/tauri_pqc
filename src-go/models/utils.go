package models

import (
	"crypto/rand"
	"encoding/hex"
)

// generateID creates a random ID string
func generateID() string {
	bytes := make([]byte, 16) // 128-bit ID
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
