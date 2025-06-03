package models

import (
	"time"
)

// Group represents a secure group for file sharing
type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	Members     []string  `json:"members"`
	SharedFiles []string  `json:"shared_files"` // File IDs
	Settings    GroupSettings `json:"settings"`
}

// GroupSettings contains group configuration
type GroupSettings struct {
	MaxFileSize           int64 `json:"max_file_size"`
	AllowHistoricalAccess bool  `json:"allow_historical_access"`
	AllowMemberInvites    bool  `json:"allow_member_invites"`
	FileRetentionDays     int   `json:"file_retention_days"`
}

// GroupCreateRequest represents the request to create a new group
type GroupCreateRequest struct {
	Name      string `json:"name"`
	CreatorID string `json:"creator_id"`
}

// GroupMemberRequest represents the request to add a member to a group
type GroupMemberRequest struct {
	UserID string `json:"user_id"`
}

// GroupResponse represents the response after group operations
type GroupResponse struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	CreatedBy string        `json:"created_by"`
	CreatedAt time.Time     `json:"created_at"`
	Members   []string      `json:"members"`
	Settings  GroupSettings `json:"settings"`
}

// NewGroup creates a new group with the specified creator
func NewGroup(name, creatorID string) *Group {
	return &Group{
		ID:          generateID(),
		Name:        name,
		CreatedBy:   creatorID,
		CreatedAt:   time.Now().UTC(),
		Members:     []string{creatorID}, // Creator is automatically a member
		SharedFiles: make([]string, 0),
		Settings:    DefaultGroupSettings(),
	}
}

// DefaultGroupSettings returns default settings for a new group
func DefaultGroupSettings() GroupSettings {
	return GroupSettings{
		MaxFileSize:           100 * 1024 * 1024, // 100 MB
		AllowHistoricalAccess: true,
		AllowMemberInvites:    false,
		FileRetentionDays:     0, // No limit
	}
}

// AddMember adds a user to the group
func (g *Group) AddMember(userID string) bool {
	// Check if user is already a member
	for _, member := range g.Members {
		if member == userID {
			return false // Already a member
		}
	}
	
	g.Members = append(g.Members, userID)
	return true
}

// RemoveMember removes a user from the group
func (g *Group) RemoveMember(userID string) bool {
	// Don't allow removing the creator
	if userID == g.CreatedBy {
		return false
	}
	
	for i, member := range g.Members {
		if member == userID {
			g.Members = append(g.Members[:i], g.Members[i+1:]...)
			return true
		}
	}
	return false
}

// IsMember checks if a user is a member of the group
func (g *Group) IsMember(userID string) bool {
	for _, member := range g.Members {
		if member == userID {
			return true
		}
	}
	return false
}

// AddSharedFile adds a file ID to the group's shared files
func (g *Group) AddSharedFile(fileID string) {
	g.SharedFiles = append(g.SharedFiles, fileID)
}

// ToResponse converts the group to a response object
func (g *Group) ToResponse() GroupResponse {
	return GroupResponse{
		ID:        g.ID,
		Name:      g.Name,
		CreatedBy: g.CreatedBy,
		CreatedAt: g.CreatedAt,
		Members:   g.Members,
		Settings:  g.Settings,
	}
}
