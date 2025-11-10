# Guide d'Utilisation de SysWhispers

## Introduction

SysWhispers est un outil qui génère automatiquement le code pour effectuer des syscalls directs. Il extrait les numéros de syscall (SSN) depuis ntdll.dll pour différentes versions de Windows.

## Localisation

L'outil SysWhispers se trouve dans :
```
tools/SysWhispers/
```

## Installation

```bash
cd tools/SysWhispers
pip install -r requirements.txt
```

## Utilisation Basique

### 1. Générer du code pour des fonctions spécifiques

```bash
python syswhispers.py -f NtAllocateVirtualMemory,NtWriteVirtualMemory,NtProtectVirtualMemory -o syscalls
```

Cela génère :
- `syscalls.h` : Header avec les prototypes
- `syscalls.asm` : Code assembleur pour les syscalls

### 2. Générer pour toutes les fonctions Nt*

```bash
python syswhispers.py --preset all -o syscalls_all
```

### 3. Générer avec des presets

```bash
# Preset pour injection de code
python syswhispers.py --preset common -o syscalls_common

# Preset pour dump de mémoire
python syswhispers.py --preset memory -o syscalls_memory
```

## Intégration dans notre projet

### Étape 1 : Générer les fichiers

```bash
cd tools/SysWhispers
python syswhispers.py -f NtAllocateVirtualMemory,NtWriteVirtualMemory,NtProtectVirtualMemory,NtCreateThreadEx,NtWaitForSingleObject,NtClose -o ../../01_Projects/Evasion/syscalls_gen
```

### Étape 2 : Compiler avec MASM (assembleur Microsoft)

Si vous utilisez Visual Studio :

```bash
ml64 /c /Fo syscalls_gen.obj syscalls_gen.asm
link /OUT:demo.exe demo.obj syscalls_gen.obj
```

Si vous utilisez GCC/MinGW :

```bash
# Convertir ASM MASM vers GAS (GNU Assembler)
# Ou utiliser notre implémentation manuelle (syscalls_indirect.c)
```

### Étape 3 : Utiliser dans le code

```c
#include "syscalls_gen.h"

int main() {
    PVOID baseAddress = NULL;
    SIZE_T size = 0x1000;
    
    // Utiliser la fonction générée par SysWhispers
    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &baseAddress,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (NT_SUCCESS(status)) {
        printf("Allocation réussie à 0x%p\n", baseAddress);
    }
    
    return 0;
}
```

## Avantages de SysWhispers

✅ **Automatisation** : Pas besoin d'écrire manuellement l'assembleur
✅ **Multi-version** : Support de plusieurs versions Windows
✅ **SSN dynamiques** : Détection automatique des numéros de syscall
✅ **Randomisation** : Peut randomiser l'ordre pour éviter les signatures

## Limitations

❌ **Nécessite MASM** : Le code ASM généré est pour Microsoft Assembler
❌ **Syscalls directs uniquement** : Ne génère pas de syscalls indirects
❌ **Détection possible** : Les instructions `syscall` restent dans le code

## Comparaison : SysWhispers vs Notre Implémentation

| Aspect | SysWhispers | Notre Code |
|--------|-------------|------------|
| **Type** | Syscalls directs | Syscalls indirects |
| **Génération** | Automatique | Manuel |
| **Furtivité** | Moyenne | Haute |
| **Complexité** | Simple | Avancée |
| **Portabilité** | Multi-version auto | Extraction dynamique PE |
| **Call stack** | Anormale | Normale (via ntdll) |

## SysWhispers2 (Version améliorée)

Une version améliorée existe : **SysWhispers2**

### Nouvelles fonctionnalités :

```bash
# Installation
git clone https://github.com/jthuraisamy/SysWhispers2
cd SysWhispers2
pip install -r requirements.txt

# Génération avec randomisation
python syswhispers.py -f NtAllocateVirtualMemory -o syscalls --randomize

# Génération avec support indirect
python syswhispers.py --preset common -o syscalls --indirect
```

### Avantages SysWhispers2 :

✅ Support des syscalls indirects (comme notre implémentation)
✅ Randomisation des noms de fonctions
✅ Obfuscation des instructions
✅ Support de plus de versions Windows

## Exercice Pratique

### 1. Générer et tester

```bash
# Aller dans le dossier SysWhispers
cd tools/SysWhispers

# Générer le code
python syswhispers.py -f NtAllocateVirtualMemory -o test_syscall

# Voir les fichiers générés
cat test_syscall.h
cat test_syscall.asm
```

### 2. Analyser les différences

Comparez le code généré par SysWhispers avec notre implémentation manuelle :

**SysWhispers (Direct)** :
```asm
NtAllocateVirtualMemory:
    mov r10, rcx
    mov eax, 18h
    syscall
    ret
```

**Notre implémentation (Indirect)** :
```asm
NtAllocateVirtualMemory_Indirect:
    mov r10, rcx
    mov eax, [ssn]        ; SSN extrait dynamiquement
    jmp [syscallAddr]     ; Jump vers ntdll (pas de syscall direct)
```

### 3. Tester la détection

Compilez le même programme avec :
1. API Windows normales (VirtualAlloc)
2. SysWhispers (syscalls directs)
3. Notre implémentation (syscalls indirects)

Testez avec Windows Defender et observez les résultats.

## Ressources

- **SysWhispers GitHub** : https://github.com/jthuraisamy/SysWhispers
- **SysWhispers2 GitHub** : https://github.com/jthuraisamy/SysWhispers2
- **SysWhispers3 GitHub** : https://github.com/klezVirus/SysWhispers3

## Alternatives

D'autres outils similaires :

- **InlineWhispers** : Intégration directe dans le code C
- **SysWhispers3** : Support ARM64, inline syscalls
- **HellsGate** : Extraction dynamique des SSN au runtime
- **HalosGate** : Amélioration de HellsGate avec gestion des hooks

## Conclusion

SysWhispers est un excellent outil pour débuter avec les syscalls, mais notre implémentation manuelle de syscalls indirects offre une meilleure furtivité pour bypasser les EDR modernes.

Pour la production :
- ✅ Utilisez des syscalls indirects (notre implémentation)
- ✅ Extrayez les SSN dynamiquement
- ✅ Évitez les instructions `syscall` dans votre code
- ✅ Maintenez une call stack légitime

Pour l'apprentissage :
- ✅ Commencez par SysWhispers pour comprendre les bases
- ✅ Analysez le code généré
- ✅ Progressez vers les syscalls indirects
- ✅ Comprenez les limitations de chaque approche
