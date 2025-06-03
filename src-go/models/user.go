package models

import (
	"time"
)

// User represents a user in the E2EE system
type User struct {
	ID             string    `json:"id"`
	Username       string    `json:"username"`
	PasswordHash   string    `json:"password_hash,omitempty"` // Omit from JSON responses
	KeyBundle      KeyBundle `json:"key_bundle"`
	CreatedAt      time.Time `json:"created_at"`
	GroupMemberships []string `json:"group_memberships"`
}

// KeyBundle contains the E2EE key material for a user
type KeyBundle struct {
	// Public keys (for other users to perform key exchange)
	PublicKeys PublicKeyBundle `json:"public_keys"`
	// Private keys (encrypted with user's password)
	PrivateKeys PrivateKeyBundle `json:"private_keys"`
	Timestamp   time.Time        `json:"timestamp"`
}

// PublicKeyBundle contains public keys for key exchange
type PublicKeyBundle struct {
	IdentityKey    []byte   `json:"identity_key"`     // Ed25519 public key
	SignedPreKey   []byte   `json:"signed_pre_key"`   // X25519 public key
	KyberPreKey    []byte   `json:"kyber_pre_key"`    // Kyber-768 public key
	OneTimePreKeys [][]byte `json:"one_time_pre_keys"` // X25519 public keys
	Signature      []byte   `json:"signature"`        // Ed25519 signature over signed pre-key
}

// PrivateKeyBundle contains encrypted private keys
type PrivateKeyBundle struct {
	IdentityKey    []byte   `json:"identity_key"`     // Encrypted Ed25519 private key
	SignedPreKey   []byte   `json:"signed_pre_key"`   // Encrypted X25519 private key
	KyberPreKey    []byte   `json:"kyber_pre_key"`    // Encrypted Kyber-768 private key
	OneTimePreKeys [][]byte `json:"one_time_pre_keys"` // Encrypted X25519 private keys
	Salt           []byte   `json:"salt"`             // Salt for key derivation
	// Individual nonces for each private key
	IdentityKeyNonce    []byte   `json:"identity_key_nonce"`     // Nonce for identity key encryption
	SignedPreKeyNonce   []byte   `json:"signed_pre_key_nonce"`   // Nonce for signed pre-key encryption
	KyberPreKeyNonce    []byte   `json:"kyber_pre_key_nonce"`    // Nonce for Kyber pre-key encryption
	OneTimePreKeysNonces [][]byte `json:"one_time_pre_keys_nonces"` // Nonces for one-time pre-keys encryption
}

// UserRegistrationRequest represents the request payload for user registration
type UserRegistrationRequest struct {
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	KeyBundle KeyBundle `json:"key_bundle"`
}

// UserResponse represents the response after successful registration
type UserResponse struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
}

// NewUser creates a new user with the given username and key bundle
func NewUser(username, passwordHash string, keyBundle KeyBundle) *User {
	return &User{
		ID:               generateID(),
		Username:         username,
		PasswordHash:     passwordHash,
		KeyBundle:        keyBundle,
		CreatedAt:        time.Now().UTC(),
		GroupMemberships: make([]string, 0),
	}
}

// AddGroupMembership adds a group ID to the user's memberships
func (u *User) AddGroupMembership(groupID string) {
	for _, id := range u.GroupMemberships {
		if id == groupID {
			return // Already a member
		}
	}
	u.GroupMemberships = append(u.GroupMemberships, groupID)
}

// RemoveGroupMembership removes a group ID from the user's memberships
func (u *User) RemoveGroupMembership(groupID string) {
	for i, id := range u.GroupMemberships {
		if id == groupID {
			u.GroupMemberships = append(u.GroupMemberships[:i], u.GroupMemberships[i+1:]...)
			return
		}
	}
}

// IsMemberOf checks if the user is a member of the specified group
func (u *User) IsMemberOf(groupID string) bool {
	for _, id := range u.GroupMemberships {
		if id == groupID {
			return true
		}
	}
	return false
}

// GetPublicKeyBundle returns the user's public key bundle for key exchange
func (u *User) GetPublicKeyBundle() PublicKeyBundle {
	return u.KeyBundle.PublicKeys
}

// ToResponse converts the user to a response object (without sensitive data)
func (u *User) ToResponse() UserResponse {
	return UserResponse{
		ID:        u.ID,
		Username:  u.Username,
		CreatedAt: u.CreatedAt,
	}
}

// PublicKeyBundleResponse represents a user's public key bundle for API responses
type PublicKeyBundleResponse struct {
	UserID     string          `json:"user_id"`
	Username   string          `json:"username"`
	PublicKeys PublicKeyBundle `json:"public_keys"`
	Timestamp  time.Time       `json:"timestamp"`
}

// ToPublicKeyBundleResponse converts the user to a public key bundle response
func (u *User) ToPublicKeyBundleResponse() PublicKeyBundleResponse {
	return PublicKeyBundleResponse{
		UserID:     u.ID,
		Username:   u.Username,
		PublicKeys: u.KeyBundle.PublicKeys,
		Timestamp:  u.KeyBundle.Timestamp,
	}
}
