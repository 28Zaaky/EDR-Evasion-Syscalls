# 🔐 EDR Evasion: Syscalls Direct & Indirect

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue.svg)](https://www.microsoft.com/windows)
[![Language](https://img.shields.io/badge/Language-C-brightgreen.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Architecture](https://img.shields.io/badge/Architecture-x64-red.svg)](https://en.wikipedia.org/wiki/X86-64)

> 📚 **Cours complet et open source sur les syscalls Windows pour l'évasion EDR**

Un cours éducatif approfondi sur les techniques de syscalls directs et indirects pour contourner les solutions de détection et réponse aux endpoints (EDR). Ce projet contient à la fois la théorie complète et des implémentations pratiques en C.

---

## ⚠️ AVERTISSEMENT LÉGAL

**Ce projet est fourni à des fins ÉDUCATIVES uniquement.**

L'utilisation de ces techniques pour des activités malveillantes ou non autorisées est **ILLÉGALE** et peut entraîner des poursuites judiciaires. Utilisez ce code uniquement dans un environnement de test contrôlé avec les autorisations appropriées.

**Consultez [DISCLAIMER.md](DISCLAIMER.md) pour plus de détails.**

---

## 📖 Table des Matières

- [À Propos](#-à-propos)
- [Fonctionnalités](#-fonctionnalités)
- [Structure du Projet](#-structure-du-projet)
- [Prérequis](#-prérequis)
- [Installation](#-installation)
- [Compilation](#-compilation)
- [Utilisation](#-utilisation)
- [Contenu Pédagogique](#-contenu-pédagogique)
- [Exemples de Code](#-exemples-de-code)
- [Détails Techniques](#-détails-techniques)
- [Détection EDR](#-détection-edr)
- [Exercices Pratiques](#-exercices-pratiques)
- [Dépannage](#-dépannage)
- [Ressources](#-ressources)
- [Contribution](#-contribution)
- [Licence](#-licence)

---

## 🎯 À Propos

Ce projet explore les techniques avancées d'évasion EDR en utilisant des **syscalls directs et indirects** sur Windows x64.

### Syscalls Directs
- Exécution de l'instruction `syscall` directement depuis le code utilisateur
- Bypass des hooks userland dans NTDLL.dll
- Extraction des SSN (System Service Numbers)

### Syscalls Indirects
- Jump vers l'instruction `syscall` légitime dans NTDLL
- Évasion de la détection des appels directs
- Parsing du format PE pour localiser les syscalls

### Concepts Couverts
- Architecture Windows (User Mode / Kernel Mode)
- Fonctionnement des EDR et hooks API
- Format PE (Portable Executable)
- Export Directory Table parsing
- Techniques d'injection de processus

---

## ✨ Fonctionnalités

- ✅ **Documentation complète** avec schémas et diagrammes
- ✅ **Implémentations fonctionnelles** en C (syscalls directs et indirects)
- ✅ **Démonstration d'injection** de shellcode dans un processus cible
- ✅ **12 exercices pratiques** progressifs (débutant → expert)
- ✅ **Guide SysWhispers** pour automatiser la génération
- ✅ **Code commenté** et expliqué ligne par ligne
- ✅ **Makefile** et scripts de compilation

---

## 📂 Structure du Projet

```
edr-evasion-syscalls/
│
├── 📄 README.md                    ← Ce fichier
├── 📄 LICENSE                      ← Licence MIT
├── 📄 DISCLAIMER.md                ← Avertissements légaux
├── 📄 .gitignore                   ← Fichiers à exclure
│
├── 📁 Docu_theorique/              ← Documentation théorique
│   ├── COURS_SYSCALLS_EDR.md      ← Cours principal (théorie complète)
│   ├── SCHEMAS_VISUELS.md         ← Diagrammes et schémas
│   ├── INDEX.md                   ← Navigation du cours
│   └── GUIDE_SYSWHISPERS.md       ← Guide d'utilisation de SysWhispers
│
├── 📁 Code_source/                 ← Implémentations C
│   ├── syscalls.h                 ← Structures et prototypes
│   ├── syscalls_direct.c          ← Syscalls directs (~450 lignes)
│   ├── syscalls_indirect.c        ← Syscalls indirects (~800 lignes)
│   └── demo_injection.c           ← Démo d'injection complète
│
├── 📁 Exo/                         ← Exercices pratiques
│   └── EXERCICES_PRATIQUES.md     ← 12 exercices progressifs
│
└── 📁 Outils_scripts/              ← Scripts et outils
    └── README.md                   ← Guide des outils
```

---

## 🔧 Prérequis

### Système d'Exploitation
- **Windows 10** ou **Windows 11** (x64)
- Machine virtuelle recommandée pour les tests

### Outils de Développement
- **GCC** (MinGW-w64) ou **MSVC**
- **Make** (optionnel)
- Éditeur de code (VS Code recommandé)

### Connaissances Recommandées
- Bases du langage C
- Notions d'architecture Windows
- Compréhension basique des appels système

---

## 💻 Installation

### 1. Cloner le Dépôt

```bash
git clone https://github.com/28Zaaky/edr-evasion-syscalls.git
cd edr-evasion-syscalls
```

### 2. Installer GCC (MinGW-w64)

#### Via MSYS2 (Recommandé)

```bash
# Télécharger et installer MSYS2 depuis https://www.msys2.org/

# Ouvrir MSYS2 et installer GCC
pacman -Syu
pacman -S mingw-w64-x86_64-gcc make
```

#### Ajouter au PATH

```
C:\msys64\mingw64\bin
```

### 3. Vérifier l'Installation

```bash
gcc --version
make --version
```

---

## 🚀 Compilation

### Avec Make (Recommandé)

```bash
cd Code_source
make
```

Options disponibles:
```bash
make all         # Compiler tous les programmes
make direct      # Syscalls directs uniquement
make indirect    # Syscalls indirects uniquement
make demo        # Démonstration complète
make clean       # Nettoyer les fichiers compilés
```

### Compilation Manuelle

Si vous n'avez pas `make`:

**Syscalls Directs:**
```bash
gcc -Wall -O2 -DCOMPILE_DEMO_DIRECT syscalls_direct.c -o syscalls_direct.exe -lntdll -s
```

**Syscalls Indirects:**
```bash
gcc -Wall -O2 -DCOMPILE_DEMO_INDIRECT syscalls_indirect.c -o syscalls_indirect.exe -lntdll -s
```

**Démo d'Injection:**
```bash
gcc -Wall -O2 demo_injection.c syscalls_indirect.c -o demo_injection.exe -lntdll -s
```

---

## 📝 Utilisation

### 1. Lire le Cours Théorique

Ouvrez `Docu_theorique/COURS_SYSCALLS_EDR.md` pour comprendre les concepts fondamentaux.

### 2. Étudier le Code Commenté

Chaque fichier `.c` contient des commentaires détaillés expliquant:
- 🎯 Le principe de chaque technique
- ⚙️ Comment le code fonctionne
- ⚠️ Les points de détection EDR
- 💡 Les bonnes pratiques

### 3. Compiler et Tester

⚠️ **Lancez toujours avec les droits administrateur**

```bash
# Tester les syscalls directs
.\syscalls_direct.exe

# Tester les syscalls indirects
.\syscalls_indirect.exe

# Tester l'injection (dans une VM isolée!)
.\demo_injection.exe
```

### 4. Analyser les Résultats

Le programme affiche chaque étape en détail:

```
╔══════════════════════════════════════════════════════╗
║       INJECTION DE SHELLCODE - ÉTAPES DÉTAILLÉES    ║
╚══════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────┐
│ ÉTAPE 1 : Allocation mémoire                        │
└─────────────────────────────────────────────────────┘
  • Protection : PAGE_READWRITE (pas RWX !)
  • Taille     : 256 bytes
  • Méthode    : NtAllocateVirtualMemory (indirect)

  ✓ Allocation réussie
    └─> Adresse : 0x0000020A12340000
    └─> Taille  : 4096 bytes
...
```

---

## 📚 Contenu Pédagogique

### 1. Cours Théorique

**[COURS_SYSCALLS_EDR.md](Docu_theorique/COURS_SYSCALLS_EDR.md)**
- Architecture Windows (User Mode / Kernel Mode)
- Fonctionnement des syscalls
- Mécanismes EDR et techniques de hooking
- Comparaison syscalls directs vs indirects
- Techniques de détection et contournement

### 2. Schémas Visuels

**[SCHEMAS_VISUELS.md](Docu_theorique/SCHEMAS_VISUELS.md)**
- Diagrammes de flux d'exécution
- Schémas d'architecture
- Visualisation des hooks
- Parsing du format PE

### 3. Guide SysWhispers

**[GUIDE_SYSWHISPERS.md](Docu_theorique/GUIDE_SYSWHISPERS.md)**
- Installation et configuration
- Génération de stubs syscall
- Intégration dans vos projets

### 4. Exercices Pratiques

**[EXERCICES_PRATIQUES.md](Exo/EXERCICES_PRATIQUES.md)**
- 12 exercices progressifs
- Du niveau débutant au niveau expert
- Solutions et explications détaillées

---

## 💡 Exemples de Code

### Exemple 1: Syscall Direct

```c
#include "syscalls.h"

// Allouer de la mémoire avec NtAllocateVirtualMemory (direct)
PVOID baseAddress = NULL;
SIZE_T regionSize = 0x1000;
NTSTATUS status;

status = NtAllocateVirtualMemory_Direct(
    GetCurrentProcess(),
    &baseAddress,
    0,
    &regionSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
);

if (NT_SUCCESS(status)) {
    printf("[+] Mémoire allouée à: 0x%p\n", baseAddress);
}
```

### Exemple 2: Syscall Indirect

```c
#include "syscalls.h"

// Initialiser les syscalls indirects
if (!InitializeIndirectSyscalls()) {
    printf("[-] Échec de l'initialisation\n");
    return 1;
}

// Utiliser NtAllocateVirtualMemory (indirect)
PVOID baseAddress = NULL;
SIZE_T regionSize = 0x1000;

NTSTATUS status = NtAllocateVirtualMemory_Indirect(
    GetCurrentProcess(),
    &baseAddress,
    0,
    &regionSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
);
```

### Exemple 3: Injection de Processus

```c
// Voir demo_injection.c pour l'exemple complet
// Pipeline: Allouer → Écrire → Protéger → Créer Thread
```

---

## 🔬 Détails Techniques

### Syscalls Directs

**Principe**: Exécuter directement l'instruction `syscall` sans passer par `ntdll.dll`.

**Avantages**:
- ✅ Bypass des hooks EDR
- ✅ Simple à implémenter

**Inconvénients**:
- ❌ Instruction `syscall` détectable dans notre code
- ❌ SSN hardcodés (différents selon Windows version)

**Code clé**:
```c
__asm__ volatile (
    "mov r10, rcx\n"
    "mov eax, 0x18\n"    // SSN de NtAllocateVirtualMemory
    "syscall\n"           // ⚠️ Instruction détectable
    "ret\n"
);
```

### Syscalls Indirects

**Principe**: Réutiliser l'instruction `syscall` qui existe déjà dans `ntdll.dll`.

**Avantages**:
- ✅ Pas d'instruction `syscall` dans notre code
- ✅ Call stack légitime (via ntdll)
- ✅ SSN extraits dynamiquement
- ✅ Plus difficile à détecter

**Inconvénients**:
- ❌ Plus complexe à implémenter
- ❌ Parsing PE nécessaire

**Processus**:
1. Charger ntdll.dll fraîche depuis le disque
2. Parser le PE pour trouver les fonctions
3. Extraire les SSN des fonctions
4. Trouver une instruction `syscall; ret`
5. Jump vers cette instruction au lieu d'exécuter notre propre syscall

**Code clé**:
```c
// Au lieu de : syscall
// On fait :
__asm__ volatile (
    "mov r10, rcx\n"
    "mov eax, %0\n"      // SSN extrait dynamiquement
    "jmp %1\n"           // Jump vers syscall dans ntdll
    :: "r"(ssn), "r"(syscallAddress)
);
```

---

## 🛡️ Détection EDR

### Ce que les EDR Voient

| Technique | Hook NTDLL | Instruction Syscall | Call Stack | Détection |
|-----------|-----------|---------------------|------------|-----------|
| **API Win32** | ✅ Oui | ❌ Non | Normale | 🔴 Haute |
| **Syscalls Directs** | ❌ Non | ✅ Oui | Anormale | 🟡 Moyenne |
| **Syscalls Indirects** | ❌ Non | ❌ Non | Normale | 🟢 Faible |

### Contre-mesures EDR Modernes

Les EDR avancés utilisent:

**1. ETW (Event Tracing for Windows)**
- Surveillance au niveau kernel
- Détection des allocations RWX
- Solution: Allouer RW → Écrire → Changer RX

**2. Kernel Callbacks**
- Interception des opérations sensibles
- PsSetCreateThreadNotifyRoutine
- Solution: Thread hijacking, APC injection

**3. Stack Walking**
- Vérification de la call stack
- Détection de return address anormales
- Solution: Syscalls indirects (stack propre)

**4. Analyse Comportementale**
- Pattern matching: Alloc → Write → Protect → Execute
- Solution: Sleep obfuscation, délais aléatoires

---

## 🧪 Exercices Pratiques

### Exercice 1: Modifier le Shellcode

Remplacez le shellcode de démonstration par un vrai shellcode:

```bash
# Générer un shellcode avec msfvenom
msfvenom -p windows/x64/exec CMD=calc.exe -f c

# L'intégrer dans demo_injection.c
```

### Exercice 2: Injection dans un Processus Distant

Modifiez le code pour injecter dans un autre processus:

```c
// Au lieu de GetCurrentProcess()
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
```

### Exercice 3: Ajouter du Chiffrement

Chiffrez le shellcode avec XOR/RC4 avant injection:

```c
// Chiffrer
for (size_t i = 0; i < size; i++) {
    shellcode[i] ^= 0xAA;
}

// Déchiffrer après écriture
for (size_t i = 0; i < size; i++) {
    ((unsigned char*)baseAddress)[i] ^= 0xAA;
}
```

### Exercice 4: Extraire les SSN Dynamiquement

Au lieu de hardcoder les SSN, extraire dynamiquement pour chaque version Windows.

---

## 🔧 Dépannage

### Erreur: "Failed to initialize indirect syscalls"

**Cause**: Impossible de lire ntdll.dll

**Solution**:
```bash
# Vérifier les permissions
icacls C:\Windows\System32\ntdll.dll

# Exécuter en administrateur
```

### Erreur: "Failed to find syscall instruction"

**Cause**: Version de Windows non supportée

**Solution**:
```c
// Modifier la recherche dans FindSyscallAddress()
// Chercher d'autres patterns: 0F 05 (sans C3)
```

### Erreur de Compilation: "undefined reference to 'DoSyscall'"

**Cause**: L'assembleur inline n'est pas compilé correctement

**Solution**:
```bash
# Compiler avec l'option -masm=intel
gcc -masm=intel syscalls_direct.c -o syscalls_direct.exe
```

---

## 📊 Comparaison des Techniques

### Performance

| Technique | Vitesse | Furtivité | Complexité |
|-----------|---------|-----------|------------|
| API Win32 | 🟢 Rapide | 🔴 Faible | 🟢 Simple |
| Syscalls Directs | 🟢 Rapide | 🟡 Moyenne | 🟡 Moyenne |
| Syscalls Indirects | 🟡 Moyenne | 🟢 Haute | 🔴 Complexe |

### Compatibilité

| Windows Version | Syscalls Directs | Syscalls Indirects |
|-----------------|------------------|-------------------|
| Windows 10 1507-1607 | ✅ SSN différents | ✅ Auto-détection |
| Windows 10 1703-1909 | ✅ SSN différents | ✅ Auto-détection |
| Windows 10 2004+ | ✅ SSN différents | ✅ Auto-détection |
| Windows 11 | ✅ SSN différents | ✅ Auto-détection |

---

## 🎓 Parcours d'Apprentissage

### Niveau 1: Débutant (2-4 heures)
1. Lire le cours théorique complet
2. Comprendre l'architecture Windows
3. Étudier les schémas visuels
4. Compiler et exécuter les exemples

### Niveau 2: Intermédiaire (4-8 heures)
1. Analyser le code des syscalls directs
2. Comprendre le parsing PE
3. Étudier les syscalls indirects
4. Faire les exercices 1-6

### Niveau 3: Avancé (8-16 heures)
1. Implémenter vos propres syscalls
2. Modifier le code d'injection
3. Faire les exercices 7-12
4. Tester contre Windows Defender

### Niveau 4: Expert (16+ heures)
1. Développer de nouvelles techniques
2. Tester contre des EDR commerciaux
3. Contribuer au projet
4. Créer vos propres outils

---

## 🧪 Environnement de Test

### Recommandations

Pour tester ces techniques en toute sécurité:

**1. Machine Virtuelle Isolée**
- VMware Workstation / VirtualBox
- Windows 10/11 x64
- Pas de connexion réseau

**2. Antivirus de Test**
- Windows Defender (inclus)
- Autre EDR gratuit (Sophos Home, etc.)
- Observer les détections

**3. Outils de Monitoring**
- Process Monitor (Sysinternals)
- Process Hacker
- API Monitor

### Scénarios de Test

```bash
# Test 1: Exécution basique
./demo_injection.exe

# Test 2: Avec Process Monitor actif
# Observer les appels système

# Test 3: Avec Windows Defender actif
# Vérifier si détecté ou non

# Test 4: Analyse du binaire
# Utiliser pestudio, PE-bear, etc.
```

---

## 📚 Ressources

### Documentation Microsoft
- [Windows Syscalls](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-nt-and-zw-versions-of-the-native-system-services-routines)
- [PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [NTDLL.dll](https://en.wikipedia.org/wiki/Microsoft_Windows_library_files#NTDLL.DLL)

### Outils Complémentaires
- [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2) - Génération automatique de stubs
- [Process Hacker](https://processhacker.sourceforge.io/) - Analyse de processus
- [x64dbg](https://x64dbg.com/) - Débogueur Windows

### Articles et Recherches
- [MDSec: Bypassing EDR](https://www.mdsec.co.uk/knowledge-centre/insights/)
- [Red Team Notes](https://www.ired.team/)
- [MalDev Academy](https://maldevacademy.com/)

### Lectures Recommandées

**1. Windows Internals** (Mark Russinovich)
- Architecture Windows en profondeur
- Gestion de la mémoire et des processus

**2. Red Team Development and Operations** (Joe Vest)
- Techniques offensives modernes
- Évasion EDR/AV

**3. Blogs et Conférences**
- https://www.mdsec.co.uk/
- https://blog.malwarebytes.com/
- https://www.ired.team/

---

## 🤝 Contribution

Les contributions sont les bienvenues! Voici comment contribuer:

1. **Fork** le projet
2. Créez une branche (`git checkout -b feature/nouvelle-technique`)
3. Committez vos changements (`git commit -m 'Ajout d'une nouvelle technique'`)
4. Poussez vers la branche (`git push origin feature/nouvelle-technique`)
5. Ouvrez une **Pull Request**

### Suggestions de Contributions
- 📝 Amélioration de la documentation
- 🐛 Correction de bugs
- ✨ Nouvelles techniques d'évasion
- 🧪 Nouveaux exercices pratiques
- 🌍 Traductions (anglais, espagnol, etc.)
- 📊 Benchmarks et tests de performance

---

## 📜 Licence

Ce projet est sous licence **MIT**. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

```
MIT License

Copyright (c) 2025 28zaaakypro@proton.me

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

[...]
```

---

## 🏆 Remerciements

- **Microsoft** pour la documentation Windows Internals
- **MDSec** pour leurs recherches sur l'évasion EDR
- **@jthuraisamy** pour SysWhispers
- **La communauté Red Team** pour le partage de connaissances
- Tous les contributeurs de ce projet

---

## 📞 Contact

Pour toute question ou suggestion:

- 📧 Email: 28zaaakypro@proton.me
- 🐛 Issues: [GitHub Issues](https://github.com/28Zaaky/edr-evasion-syscalls/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/28Zaaky/edr-evasion-syscalls/discussions)

---

## ⭐ Soutenir le Projet

Si ce projet vous a été utile:

- ⭐ **Star** le dépôt
- 🔄 **Fork** et contribuez
- 📢 **Partagez** avec la communauté
- 📝 **Écrivez** un article ou tutoriel

---

<div align="center">

**Développé avec ❤️ pour la communauté de sécurité offensive**

📚 **Apprenez** | 🛡️ **Défendez** | 🎓 **Partagez**

---

*Dernière mise à jour: Novembre 2025*

</div>
