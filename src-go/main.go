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

	// Create HTTP server mux
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", healthCheckHandler)

	// Authentication endpoints
	mux.HandleFunc("/register", authHandler.RegisterUser)
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

	// File endpoints
	mux.HandleFunc("/files/", func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a file content request
		if r.Method == http.MethodGet && containsPath(r.URL.Path, "/content") {
			fileHandler.GetFileContent(w, r)
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
	fmt.Printf("📋 Available endpoints:\n")
	fmt.Printf("   GET  /health                           - Health check\n")
	fmt.Printf("   POST /register                         - Register new user\n")
	fmt.Printf("   POST /public-key-bundles               - Get public key bundles\n")
	fmt.Printf("   POST /groups                           - Create new group\n")
	fmt.Printf("   POST /groups/{groupId}/members         - Add member to group\n")
	fmt.Printf("   POST /groups/{groupId}/wrapped-keys    - Add wrapped keys for new member\n")
	fmt.Printf("   POST /groups/{groupId}/files           - Share file in group\n")
	fmt.Printf("   GET  /groups/{groupId}/files           - List files in group\n")
	fmt.Printf("   GET  /files/{fileId}/content           - Get file content and wrapped key\n")
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
