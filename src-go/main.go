package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"e2ee-backend/handlers"
	"e2ee-backend/middleware"
	"e2ee-backend/storage"
	"e2ee-backend/utils"
)

func main() {
	// Get port from environment variable or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Initialize storage
	store := storage.NewMemoryStorage()

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(store)
	groupHandler := handlers.NewGroupHandler(store)
	fileHandler := handlers.NewFileHandler(store)
	messageHandler := handlers.NewMessageHandler(store)
	blobHandler := handlers.NewBlobHandler("./blobs") // Local blob storage directory

	// Create HTTP server mux
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", healthCheckHandler)

	// Authentication endpoints
	mux.HandleFunc("/register", authHandler.RegisterUser)
	mux.HandleFunc("/login", authHandler.LoginUser)
	mux.HandleFunc("/users/by-username/", authHandler.GetUserByUsername)
	mux.HandleFunc("/public-key-bundles", authHandler.GetPublicKeyBundles)

	// Group endpoints
	mux.HandleFunc("/groups", groupHandler.CreateGroup)
	mux.HandleFunc("/groups/", func(w http.ResponseWriter, r *http.Request) {
		// Route based on the path structure
		if r.URL.Path == "/groups" || r.URL.Path == "/groups/" {
			groupHandler.CreateGroup(w, r)
			return
		}

		// Check if it's a member addition request
		if r.Method == http.MethodPost && containsPath(r.URL.Path, "/members") {
			groupHandler.AddMember(w, r)
			return
		}

		// Check if it's a wrapped keys request
		if r.Method == http.MethodPost && containsPath(r.URL.Path, "/wrapped-keys") {
			groupHandler.AddWrappedKeysForNewMember(w, r)
			return
		}

		// Check if it's a file operation request
		if containsPath(r.URL.Path, "/files") {
			if r.Method == http.MethodPost {
				fileHandler.ShareFile(w, r)
			} else if r.Method == http.MethodGet {
				fileHandler.GetGroupFiles(w, r)
			} else {
				utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
			}
			return
		}

		utils.WriteNotFoundResponse(w, "Endpoint not found")
	})

	// File endpoints (zero-knowledge)
	mux.HandleFunc("/files/", func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a file info request
		if r.Method == http.MethodGet && containsPath(r.URL.Path, "/info") {
			fileHandler.GetFileInfo(w, r)
			return
		}

		utils.WriteNotFoundResponse(w, "Endpoint not found")
	})

	// Blob storage endpoints
	mux.HandleFunc("/blobs/upload", blobHandler.UploadBlob)
	mux.HandleFunc("/blobs/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if containsPath(r.URL.Path, "/list") {
				blobHandler.ListBlobs(w, r)
			} else {
				blobHandler.DownloadBlob(w, r)
			}
		case http.MethodHead:
			blobHandler.GetBlobInfo(w, r)
		case http.MethodDelete:
			blobHandler.DeleteBlob(w, r)
		default:
			utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})

	// Message queue endpoints
	mux.HandleFunc("/messages/send", messageHandler.SendWrappedKey)
	mux.HandleFunc("/messages/send-bulk", messageHandler.SendBulkWrappedKeys)
	mux.HandleFunc("/messages/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch && containsPath(r.URL.Path, "/processed") {
			messageHandler.MarkMessageProcessed(w, r)
			return
		}
		utils.WriteNotFoundResponse(w, "Endpoint not found")
	})

	// Update user endpoints to include message queue access
	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		if containsPath(r.URL.Path, "/messages") {
			if containsPath(r.URL.Path, "/unprocessed") {
				messageHandler.GetUnprocessedMessages(w, r)
			} else {
				messageHandler.GetUserMessages(w, r)
			}
			return
		}
		if containsPath(r.URL.Path, "/by-username/") {
			authHandler.GetUserByUsername(w, r)
			return
		}
		utils.WriteNotFoundResponse(w, "Endpoint not found")
	})

	// Apply middleware
	handler := middleware.CORSMiddleware(
		middleware.LoggingMiddleware(
			middleware.ContentTypeMiddleware(mux),
		),
	)

	// Start server
	addr := ":" + port
	fmt.Printf("🚀 E2EE Backend Server starting on port %s\n", port)
	fmt.Printf("📋 Available endpoints (Zero-Knowledge E2EE):\n")
	fmt.Printf("   GET  /health                           - Health check\n")
	fmt.Printf("   POST /register                         - Register new user\n")
	fmt.Printf("   POST /login                            - Login user\n")
	fmt.Printf("   GET  /users/by-username/{username}     - Get user by username\n")
	fmt.Printf("   GET  /users/{userId}/messages          - Get user's message queue\n")
	fmt.Printf("   GET  /users/{userId}/messages/unprocessed - Get unprocessed messages\n")
	fmt.Printf("   POST /public-key-bundles               - Get public key bundles\n")
	fmt.Printf("   POST /groups                           - Create new group\n")
	fmt.Printf("   POST /groups/{groupId}/members         - Add member to group\n")
	fmt.Printf("   POST /groups/{groupId}/wrapped-keys    - Add wrapped keys for new member\n")
	fmt.Printf("   POST /groups/{groupId}/files           - Share file metadata in group\n")
	fmt.Printf("   GET  /groups/{groupId}/files           - List files in group\n")
	fmt.Printf("   GET  /files/{fileId}/info              - Get file metadata (no keys/content)\n")
	fmt.Printf("   POST /blobs/upload                     - Upload encrypted blob\n")
	fmt.Printf("   GET  /blobs/{blobId}                   - Download encrypted blob\n")
	fmt.Printf("   POST /messages/send                    - Send wrapped key to user\n")
	fmt.Printf("   POST /messages/send-bulk               - Send wrapped keys to multiple users\n")
	fmt.Printf("   PATCH /messages/{messageId}/processed  - Mark message as processed\n")
	fmt.Printf("\n🔒 Server supports E2EE file sharing with in-memory storage\n")
	fmt.Printf("🌐 CORS enabled for all origins\n")
	fmt.Printf("📝 Request logging enabled\n\n")

	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

// healthCheckHandler handles health check requests
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.WriteErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	utils.WriteSuccessResponse(w, map[string]interface{}{
		"status":  "healthy",
		"service": "e2ee-backend",
		"version": "1.0.0",
	})
}

// containsPath checks if a URL path contains a specific segment
func containsPath(path, segment string) bool {
	return len(path) > len(segment) &&
		(path[len(path)-len(segment):] == segment ||
			path[len(path)-len(segment)-1:len(path)-len(segment)] == "/")
}
