//go:build windows
// +build windows

// rawSyscall6 — 直接执行SYSCALL指令，6个参数
// 绕过所有用户态EDR hook，通过SSN直接进入内核
TEXT ·rawSyscall6(SB),0,$0-64
    MOVL ssn+0(FP), AX          // EAX = syscall number
    MOVQ a1+8(FP), CX           // RCX = arg1
    MOVQ CX, R10                // R10 = RCX (Windows: mov r10, rcx)
    MOVQ a2+16(FP), DX          // RDX = arg2
    MOVQ a3+24(FP), R8          // R8 = arg3
    MOVQ a4+32(FP), R9          // R9 = arg4
    MOVQ a5+40(FP), R11         // temp: a5
    MOVQ a6+48(FP), R12         // temp: a6
    MOVQ R11, a4+32(FP)         // [arg5 on stack for SYSCALL]
    MOVQ R12, a5+40(FP)         // [arg6 on stack for SYSCALL]
    SYSCALL                     // 0F 05 — enter kernel
    MOVQ AX, ret+56(FP)         // Store NTSTATUS return value
    RET

// rawSyscall4 — 直接执行SYSCALL指令，4个参数
TEXT ·rawSyscall4(SB),0,$0-48
    MOVL ssn+0(FP), AX          // EAX = syscall number
    MOVQ a1+8(FP), CX           // RCX = arg1
    MOVQ CX, R10                // R10 = RCX
    MOVQ a2+16(FP), DX          // RDX = arg2
    MOVQ a3+24(FP), R8          // R8 = arg3
    MOVQ a4+32(FP), R9          // R9 = arg4
    SYSCALL                     // 0F 05
    MOVQ AX, ret+40(FP)         // Store NTSTATUS
    RET
