package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
)

// User struct representing a user profile
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	// Add other profile fields as needed
}

// Define MongoDB schemas and models for users (assuming MongoDB usage)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	router := mux.NewRouter()

	// Routes
	router.HandleFunc("/register", registerHandler).Methods("POST")
	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.HandleFunc("/profile", profileHandler).Methods("GET")
	router.HandleFunc("/profile/update", updateProfileHandler).Methods("PUT")
	router.HandleFunc("/profile/update-picture", updateProfilePictureHandler).Methods("PUT")
	router.HandleFunc("/profile/{id}", viewProfileHandler).Methods("GET")
	router.HandleFunc("/upload", uploadHandler).Methods("POST")
	router.HandleFunc("/video/{id}", videoHandler).Methods("GET")

	// Set up CORS
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})
	handler := c.Handler(router)

	// Serve static files (videos)
	router.PathPrefix("/videos/").Handler(http.StripPrefix("/videos/", http.FileServer(http.Dir("./videos"))))

	// Clean up uploaded files after a certain period
	go func() {
		for {
			err := cleanUpFiles("./videos")
			if err != nil {
				log.Println("Error cleaning up files:", err)
			}
			time.Sleep(24 * time.Hour)
		}
	}()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Println("Server is running on port", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	// Handle user registration
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Handle user login
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve and return user's own profile information
}

func updateProfileHandler(w http.ResponseWriter, r *http.Request) {
	// Update user's profile information
}

func updateProfilePictureHandler(w http.ResponseWriter, r *http.Request) {
	// Update user's profile picture
}

func viewProfileHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve and return other user's profile information
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	// Handle video upload
}

func videoHandler(w http.ResponseWriter, r *http.Request) {
	// Handle serving video file
}

func cleanUpFiles(dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		return err
	}
	for _, file := range files {
		err := os.Remove(file)
		if err != nil {
			return err
		}
	}
	return nil
}