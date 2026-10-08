package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type User struct {
	UserID       int    `json:"user_id"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

type UserCreateRequest struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

type UserCreateResponse struct {
	Status string `json:"status"`
	UserID int    `json:"user_id"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	Message   string `json:"message"`
}

type Database struct {
	sync.RWMutex
	users  map[string]User
	nextID int64
	logs   []LogEntry
}

var db = &Database{
	users:  make(map[string]User),
	nextID: 100,
	logs:   make([]LogEntry, 0),
}

func (d *Database) addLog(method, path string, status int, msg string) {
	d.Lock()
	defer d.Unlock()
	entry := LogEntry{
		Timestamp: time.Now().Format("15:04:05.000"),
		Method:    method,
		Path:      path,
		Status:    status,
		Message:   msg,
	}
	d.logs = append(d.logs, entry)
	if len(d.logs) > 50 {
		d.logs = d.logs[1:]
	}
}

func withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Cookie")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

// POST /db/users
func handleCreateUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req UserCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.PasswordHash == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid payload"})
		db.addLog(r.Method, r.URL.Path, http.StatusBadRequest, "Invalid request body")
		return
	}

	db.Lock()
	defer db.Unlock()

	if _, exists := db.users[req.Username]; exists {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Username already exists"})
		db.addLog(r.Method, r.URL.Path, http.StatusBadRequest, fmt.Sprintf("Collision: %s", req.Username))
		return
	}

	newID := int(atomic.AddInt64(&db.nextID, 1))
	newUser := User{
		UserID:       newID,
		Username:     req.Username,
		PasswordHash: req.PasswordHash,
	}
	db.users[req.Username] = newUser

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(UserCreateResponse{
		Status: "ok",
		UserID: newID,
	})
	db.addLog(r.Method, r.URL.Path, http.StatusCreated, fmt.Sprintf("Registered user %s (#%d)", req.Username, newID))
}

// GET /db/users/{username}
func handleGetUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != "db" || parts[1] != "users" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid route format"})
		return
	}

	username := parts[2]

	db.RLock()
	user, exists := db.users[username]
	db.RUnlock()

	if !exists {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "User not found"})
		db.addLog(r.Method, r.URL.Path, http.StatusNotFound, fmt.Sprintf("Missing user: %s", username))
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
	db.addLog(r.Method, r.URL.Path, http.StatusOK, fmt.Sprintf("Fetched user %s", username))
}

// Router dispatcher for /db/users and /db/users/{username}
func usersDispatcher(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(r.URL.Path, "/")
	if path == "db/users" {
		handleCreateUser(w, r)
		return
	}
	handleGetUser(w, r)
}

// Bonus Monitoring Log API: GET /logs
func handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	db.RLock()
	defer db.RUnlock()
	json.NewEncoder(w).Encode(db.logs)
}

func main() {
	port := "8083" // Default DB port
	mux := http.NewServeMux()

	mux.HandleFunc("/db/users", withCORS(usersDispatcher))
	mux.HandleFunc("/db/users/", withCORS(usersDispatcher))
	mux.HandleFunc("/logs", withCORS(handleLogs))

	log.Printf("🚀 [acm-db] Database service listening on port :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Fatal: %v", err)
	}
}
