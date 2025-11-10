;===============================================================================
; DoSyscall - Indirect Syscall Stub
;===============================================================================
; Effectue un appel syscall indirect via une adresse ntdll
;
; Paramètres (Windows x64 calling convention):
;   RCX = ssn (System Service Number)
;   RDX = syscallAddr (adresse du syscall;ret dans ntdll)
;   R8  = arg1
;   R9  = arg2
;   [RSP+0x28] = arg3
;   [RSP+0x30] = arg4
;   [RSP+0x38] = arg5
;   [RSP+0x40] = arg6
;
; Convention syscall (différente de Windows x64):
;   EAX = SSN
;   R10 = arg1  (au lieu de RCX)
;   RDX = arg2  (pas RCX comme Windows)
;   R8  = arg3  (pas RDX comme Windows)
;   R9  = arg4  (pas R8 comme Windows)
;   [RSP+0x28] = arg5
;   [RSP+0x30] = arg6
;===============================================================================

.code

DoSyscall PROC
    ; Sauvegarder l'adresse syscall sur la pile
    push rdx                     ; [RSP] = syscallAddr
    sub rsp, 20h                 ; Shadow space (32 bytes)
    
    ; Préparer les registres pour syscall
    mov r10, r8                  ; R10 = arg1 (convention syscall)
    mov eax, ecx                 ; EAX = SSN
    
    ; Charger les arguments depuis la pile
    ; Offset ajusté : +28h (shadow) +8 (push) = +30h
    mov rcx, r9                  ; RCX = arg2
    mov rdx, [rsp+50h]           ; RDX = arg3 (offset: +20h shadow +8 push +28h = +50h)
    mov r8, [rsp+58h]            ; R8  = arg4
    mov r9, [rsp+60h]            ; R9  = arg5
    
    ; Les arguments arg5 et arg6 restent sur la pile (position correcte)
    
    ; Récupérer l'adresse syscall et appeler
    mov r11, [rsp+20h]           ; R11 = syscallAddr (après shadow space)
    call r11                     ; Appel indirect du syscall
    
    ; Nettoyer la pile
    add rsp, 20h                 ; Retirer shadow space
    add rsp, 8                   ; Retirer le push rdx
    
    ; RAX contient le NTSTATUS de retour
    ret
DoSyscall ENDP

END
