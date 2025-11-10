#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <windows.h>

// ============================================================================
// STRUCTURES ET DÉFINITIONS NTAPI
// ============================================================================

// Structure pour les informations de base d'un objet
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;  // PUNICODE_STRING
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// Macro d'initialisation des OBJECT_ATTRIBUTES
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}

// Structure CLIENT_ID pour identifier un processus/thread
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// États NTSTATUS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
typedef LONG NTSTATUS;

// ============================================================================
// PROTOTYPES DES SYSCALLS DIRECTS
// ============================================================================

// NtAllocateVirtualMemory : Alloue de la mémoire dans un processus
// Paramètres :
//   - ProcessHandle : Handle du processus cible
//   - BaseAddress : Adresse de base souhaitée (peut être NULL pour auto)
//   - ZeroBits : Doit être 0
//   - RegionSize : Taille de la région à allouer
//   - AllocationType : Type d'allocation (MEM_COMMIT | MEM_RESERVE)
//   - Protect : Protection mémoire (PAGE_READWRITE, PAGE_EXECUTE_READ, etc.)
NTSTATUS NtAllocateVirtualMemory_Direct(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

// NtWriteVirtualMemory : Écrit dans la mémoire d'un processus
// Paramètres :
//   - ProcessHandle : Handle du processus cible
//   - BaseAddress : Adresse où écrire
//   - Buffer : Buffer contenant les données à écrire
//   - NumberOfBytesToWrite : Nombre d'octets à écrire
//   - NumberOfBytesWritten : Pointeur recevant le nombre d'octets écrits
NTSTATUS NtWriteVirtualMemory_Direct(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

// NtProtectVirtualMemory : Change les protections mémoire
// Paramètres :
//   - ProcessHandle : Handle du processus
//   - BaseAddress : Adresse de base de la région
//   - RegionSize : Taille de la région
//   - NewProtect : Nouvelle protection (PAGE_EXECUTE_READ, etc.)
//   - OldProtect : Pointeur recevant l'ancienne protection
NTSTATUS NtProtectVirtualMemory_Direct(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

// NtCreateThreadEx : Crée un thread dans un processus
// Paramètres :
//   - ThreadHandle : Pointeur recevant le handle du thread
//   - DesiredAccess : Accès souhaité (THREAD_ALL_ACCESS)
//   - ObjectAttributes : Attributs de l'objet (peut être NULL)
//   - ProcessHandle : Handle du processus
//   - StartRoutine : Adresse de la fonction de démarrage
//   - Argument : Argument passé à la fonction
//   - CreateFlags : Flags de création (0 ou CREATE_SUSPENDED)
//   - ZeroBits : Doit être 0
//   - StackSize : Taille de la stack (0 pour défaut)
//   - MaximumStackSize : Taille max de la stack (0 pour défaut)
//   - AttributeList : Liste d'attributs (peut être NULL)
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
);

// NtWaitForSingleObject : Attend qu'un objet soit signalé
// Paramètres :
//   - Handle : Handle de l'objet à attendre
//   - Alertable : TRUE si l'attente peut être interrompue par une APC
//   - Timeout : Durée d'attente (NULL pour infini)
NTSTATUS NtWaitForSingleObject_Direct(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);

// NtClose : Ferme un handle
NTSTATUS NtClose_Direct(
    HANDLE Handle
);

// ============================================================================
// PROTOTYPES DES SYSCALLS INDIRECTS
// ============================================================================

// Mêmes fonctions mais avec implémentation indirecte
NTSTATUS NtAllocateVirtualMemory_Indirect(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

NTSTATUS NtWriteVirtualMemory_Indirect(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

NTSTATUS NtProtectVirtualMemory_Indirect(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

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
    PVOID AttributeList
);

NTSTATUS NtWaitForSingleObject_Indirect(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);

NTSTATUS NtClose_Indirect(
    HANDLE Handle
);

// ============================================================================
// FONCTIONS UTILITAIRES
// ============================================================================

// Initialise le système de syscalls indirects
// Charge une copie fraîche de ntdll.dll et trouve l'adresse syscall
BOOL InitializeIndirectSyscalls();

// Nettoie les ressources des syscalls indirects
VOID CleanupIndirectSyscalls();

// Affiche un message d'erreur formaté
VOID PrintError(const char* function, NTSTATUS status);

// Affiche un message de succès
VOID PrintSuccess(const char* message);

#endif // SYSCALLS_H
