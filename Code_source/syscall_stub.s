/*
 * ============================================================================
 * SYSCALL STUB - Assembleur externe pour les syscalls indirects
 * ============================================================================
 * 
 * Cette fonction effectue le syscall indirect en préparant les registres
 * et en sautant vers l'instruction syscall dans ntdll.dll
 */

    .global DoIndirectSyscall
    .intel_syntax noprefix

DoIndirectSyscall:
    # RCX = SSN (System Service Number)
    # RDX = Adresse syscall dans ntdll
    # R8  = Arg1 (ProcessHandle)
    # R9  = Arg2
    # [RSP+0x28] = Arg3
    # [RSP+0x30] = Arg4
    # etc.
    
    mov r10, r8         # R10 = premier argument
    mov eax, ecx        # EAX = SSN
    
    # Décaler les arguments
    mov rcx, r9         # RCX = Arg2
    mov r8, [rsp+0x28]  # R8  = Arg3
    mov r9, [rsp+0x30]  # R9  = Arg4
    
    # Préparer la pile (shadow space + align)
    sub rsp, 0x28
    
    # Sauvegarder l'adresse syscall et appeler
    push rdx
    pop r11
    call r11
    
    # Restaurer la pile
    add rsp, 0x28
    
    ret
