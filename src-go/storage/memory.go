package storage

import (
	"errors"
	"sync"

	"e2ee-backend/models"
)

// MemoryStorage provides in-memory storage for the application
type MemoryStorage struct {
	users  map[string]*models.User
	groups map[string]*models.Group
	files  map[string]*models.SharedFile

	// Message queue system for wrapped keys
	messageQueues map[string]*models.MessageQueue   // userID -> MessageQueue
	messages      map[string]*models.WrappedMessage // messageID -> WrappedMessage

	// Maps for lookups
	usersByUsername map[string]*models.User
	filesByGroup    map[string][]string // groupID -> []fileID

	mutex sync.RWMutex
}

// NewMemoryStorage creates a new in-memory storage instance
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		users:           make(map[string]*models.User),
		groups:          make(map[string]*models.Group),
		files:           make(map[string]*models.SharedFile),
		messageQueues:   make(map[string]*models.MessageQueue),
		messages:        make(map[string]*models.WrappedMessage),
		usersByUsername: make(map[string]*models.User),
		filesByGroup:    make(map[string][]string),
	}
}

// User operations

// CreateUser stores a new user
func (s *MemoryStorage) CreateUser(user *models.User) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if username already exists
	if _, exists := s.usersByUsername[user.Username]; exists {
		return errors.New("username already exists")
	}

	s.users[user.ID] = user
	s.usersByUsername[user.Username] = user
	return nil
}

// GetUser retrieves a user by ID
func (s *MemoryStorage) GetUser(userID string) (*models.User, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	user, exists := s.users[userID]
	if !exists {
		return nil, errors.New("user not found")
	}
	return user, nil
}

// GetUserByUsername retrieves a user by username
func (s *MemoryStorage) GetUserByUsername(username string) (*models.User, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	user, exists := s.usersByUsername[username]
	if !exists {
		return nil, errors.New("user not found")
	}
	return user, nil
}

// UpdateUser updates an existing user
func (s *MemoryStorage) UpdateUser(user *models.User) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.users[user.ID]; !exists {
		return errors.New("user not found")
	}

	s.users[user.ID] = user
	s.usersByUsername[user.Username] = user
	return nil
}

// Group operations

// CreateGroup stores a new group
func (s *MemoryStorage) CreateGroup(group *models.Group) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.groups[group.ID] = group
	s.filesByGroup[group.ID] = make([]string, 0)
	return nil
}

// GetGroup retrieves a group by ID
func (s *MemoryStorage) GetGroup(groupID string) (*models.Group, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	group, exists := s.groups[groupID]
	if !exists {
		return nil, errors.New("group not found")
	}
	return group, nil
}

// UpdateGroup updates an existing group
func (s *MemoryStorage) UpdateGroup(group *models.Group) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.groups[group.ID]; !exists {
		return errors.New("group not found")
	}

	s.groups[group.ID] = group
	return nil
}

// GetGroupsByUser retrieves all groups a user is a member of
func (s *MemoryStorage) GetGroupsByUser(userID string) ([]*models.Group, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var userGroups []*models.Group
	for _, group := range s.groups {
		if group.IsMember(userID) {
			userGroups = append(userGroups, group)
		}
	}
	return userGroups, nil
}

// File operations

// CreateFile stores a new shared file
func (s *MemoryStorage) CreateFile(file *models.SharedFile) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.files[file.ID] = file

	// Add to group's file list
	if fileList, exists := s.filesByGroup[file.GroupID]; exists {
		s.filesByGroup[file.GroupID] = append(fileList, file.ID)
	} else {
		s.filesByGroup[file.GroupID] = []string{file.ID}
	}

	return nil
}

// GetFile retrieves a file by ID
func (s *MemoryStorage) GetFile(fileID string) (*models.SharedFile, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	file, exists := s.files[fileID]
	if !exists {
		return nil, errors.New("file not found")
	}
	return file, nil
}

// GetFilesByGroup retrieves all files in a group
func (s *MemoryStorage) GetFilesByGroup(groupID string) ([]*models.SharedFile, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	fileIDs, exists := s.filesByGroup[groupID]
	if !exists {
		return []*models.SharedFile{}, nil
	}

	var files []*models.SharedFile
	for _, fileID := range fileIDs {
		if file, exists := s.files[fileID]; exists {
			files = append(files, file)
		}
	}

	return files, nil
}

// UpdateFile updates an existing file
func (s *MemoryStorage) UpdateFile(file *models.SharedFile) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.files[file.ID]; !exists {
		return errors.New("file not found")
	}

	s.files[file.ID] = file
	return nil
}

// Message Queue operations

// SendWrappedMessage adds a wrapped message to a user's inbox
func (s *MemoryStorage) SendWrappedMessage(message *models.WrappedMessage) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Store the message
	s.messages[message.ID] = message

	// Add to user's queue
	queue, exists := s.messageQueues[message.RecipientID]
	if !exists {
		queue = &models.MessageQueue{
			UserID:   message.RecipientID,
			Messages: make([]*models.WrappedMessage, 0),
		}
		s.messageQueues[message.RecipientID] = queue
	}

	queue.Messages = append(queue.Messages, message)
	return nil
}

// GetUserMessages retrieves all messages for a user
func (s *MemoryStorage) GetUserMessages(userID string) ([]*models.WrappedMessage, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	queue, exists := s.messageQueues[userID]
	if !exists {
		return []*models.WrappedMessage{}, nil
	}

	return queue.Messages, nil
}

// GetUnprocessedMessages retrieves unprocessed messages for a user
func (s *MemoryStorage) GetUnprocessedMessages(userID string) ([]*models.WrappedMessage, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	queue, exists := s.messageQueues[userID]
	if !exists {
		return []*models.WrappedMessage{}, nil
	}

	var unprocessed []*models.WrappedMessage
	for _, message := range queue.Messages {
		if !message.Processed {
			unprocessed = append(unprocessed, message)
		}
	}

	return unprocessed, nil
}

// MarkMessageProcessed marks a message as processed
func (s *MemoryStorage) MarkMessageProcessed(messageID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	message, exists := s.messages[messageID]
	if !exists {
		return errors.New("message not found")
	}

	message.MarkProcessed()
	return nil
}
