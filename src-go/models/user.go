package models

import (
	"time"
)

// User represents a user in the E2EE system
// SECURITY: Only stores public information - NO private keys or passwords
type User struct {
	ID               string          `json:"id"`
	Username         string          `json:"username"`
	PublicKeyBundle  PublicKeyBundle `json:"public_key_bundle"`
	CreatedAt        time.Time       `json:"created_at"`
	GroupMemberships []string        `json:"group_memberships"`
}

// REMOVED: KeyBundle - server should never store private keys

// PublicKeyBundle contains public keys for key exchange
type PublicKeyBundle struct {
	IdentityKey    []byte   `json:"identity_key"`      // Ed25519 public key
	SignedPreKey   []byte   `json:"signed_pre_key"`    // X25519 public key
	KyberPreKey    []byte   `json:"kyber_pre_key"`     // Kyber-768 public key
	OneTimePreKeys [][]byte `json:"one_time_pre_keys"` // X25519 public keys
	Signature      []byte   `json:"signature"`         // Ed25519 signature over signed pre-key
}

// REMOVED: PrivateKeyBundle - server should NEVER store private keys

// UserRegistrationRequest represents the request payload for user registration
// SECURITY: Only accepts public key bundle - NO private keys or passwords
type UserRegistrationRequest struct {
	Username        string          `json:"username"`
	PublicKeyBundle PublicKeyBundle `json:"public_key_bundle"`
}

// UserResponse represents the response after successful registration
type UserResponse struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
}

// NewUser creates a new user with the given username and public key bundle
// SECURITY: Only accepts public key bundle - NO private keys or passwords
func NewUser(username string, publicKeyBundle PublicKeyBundle) *User {
	return &User{
		ID:               generateID(),
		Username:         username,
		PublicKeyBundle:  publicKeyBundle,
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
	return u.PublicKeyBundle
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
		PublicKeys: u.PublicKeyBundle,
		Timestamp:  u.CreatedAt, // Use user creation time as timestamp
	}
}
