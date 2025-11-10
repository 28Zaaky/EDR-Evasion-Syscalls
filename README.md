# 🔐 EDR Evasion: Syscalls Direct & Indirect# 📚 SYSCALLS DIRECTS ET INDIRECTS - Guide Pratique



[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)## 📖 Introduction

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue.svg)](https://www.microsoft.com/windows)

[![Language](https://img.shields.io/badge/Language-C-brightgreen.svg)](https://en.wikipedia.org/wiki/C_(programming_language))Ce projet contient un **cours complet** et des **implémentations pratiques** sur les syscalls directs et indirects pour l'évasion EDR (Endpoint Detection and Response).

[![Architecture](https://img.shields.io/badge/Architecture-x64-red.svg)](https://en.wikipedia.org/wiki/X86-64)

### 📁 Contenu du dossier

> 📚 **Cours complet et open source sur les syscalls Windows pour l'évasion EDR**

```

Un cours éducatif approfondi sur les techniques de syscalls directs et indirects pour contourner les solutions de détection et réponse aux endpoints (EDR). Ce projet contient à la fois la théorie complète et des implémentations pratiques en C.Evasion/

├── COURS_SYSCALLS_EDR.md      # Cours théorique complet

---├── syscalls.h                  # Header avec structures et prototypes

├── syscalls_direct.c           # Implémentation syscalls directs

## ⚠️ AVERTISSEMENT LÉGAL├── syscalls_indirect.c         # Implémentation syscalls indirects

├── demo_injection.c            # Démonstration pratique complète

**Ce projet est fourni à des fins ÉDUCATIVES uniquement.**├── Makefile                    # Compilation automatique

└── README.md                   # Ce fichier

L'utilisation de ces techniques pour des activités malveillantes ou non autorisées est **ILLÉGALE** et peut entraîner des poursuites judiciaires. Utilisez ce code uniquement dans un environnement de test contrôlé avec les autorisations appropriées.```



**Consultez [DISCLAIMER.md](DISCLAIMER.md) pour plus de détails.**---



---## 🎯 Objectifs Pédagogiques



## 📖 Table des Matières### Partie Théorique

✅ Comprendre l'architecture User Mode / Kernel Mode  

- [À Propos](#-à-propos)✅ Comprendre comment fonctionnent les EDR et leurs hooks  

- [Fonctionnalités](#-fonctionnalités)✅ Apprendre les différences entre syscalls directs et indirects  

- [Structure du Projet](#-structure-du-projet)✅ Connaître les techniques de détection et contre-mesures  

- [Prérequis](#-prérequis)

- [Installation](#-installation)### Partie Pratique

- [Utilisation](#-utilisation)✅ Implémenter des syscalls directs en C + ASM  

- [Contenu Pédagogique](#-contenu-pédagogique)✅ Implémenter des syscalls indirects (plus furtifs)  

- [Exemples](#-exemples)✅ Parser le format PE pour extraire les SSN  

- [Contribution](#-contribution)✅ Réaliser une injection de shellcode complète  

- [Licence](#-licence)

- [Ressources](#-ressources)---



---## 🚀 Compilation



## 🎯 À Propos### Prérequis



Ce projet explore les techniques avancées d'évasion EDR en utilisant des **syscalls directs et indirects** sur Windows x64. Il couvre:- **GCC** (MinGW-w64 sur Windows)

- **Windows 10/11** x64

### Syscalls Directs- Droits administrateur (pour certaines opérations)

- Exécution de l'instruction `syscall` directement depuis le code utilisateur

- Bypass des hooks userland dans NTDLL.dll### Compilation Simple

- Extraction des SSN (System Service Numbers)

```bash

### Syscalls Indirects# Compiler tous les programmes

- Jump vers l'instruction `syscall` légitime dans NTDLLmake all

- Évasion de la détection des appels directs

- Parsing du format PE pour localiser les syscalls# Compiler uniquement une cible spécifique

make direct      # Syscalls directs

### Concepts Couvertsmake indirect    # Syscalls indirects

- Architecture Windows (User Mode / Kernel Mode)make demo        # Démonstration complète

- Fonctionnement des EDR et hooks API

- Format PE (Portable Executable)# Nettoyer les fichiers compilés

- Export Directory Table parsingmake clean

- Techniques d'injection de processus```



---### Compilation Manuelle



## ✨ FonctionnalitésSi vous n'avez pas `make` :



- ✅ **Documentation complète** avec schémas et diagrammes```bash

- ✅ **Implémentations fonctionnelles** en C (syscalls directs et indirects)# Syscalls directs

- ✅ **Démonstration d'injection** de shellcode dans un processus ciblegcc -Wall -O2 -DCOMPILE_DEMO_DIRECT syscalls_direct.c -o syscalls_direct.exe -lntdll -s

- ✅ **12 exercices pratiques** progressifs (débutant → expert)

- ✅ **Guide SysWhispers** pour automatiser la génération# Syscalls indirects

- ✅ **Code commenté** et expliqué ligne par lignegcc -Wall -O2 -DCOMPILE_DEMO_INDIRECT syscalls_indirect.c -o syscalls_indirect.exe -lntdll -s

- ✅ **Makefile** et scripts de compilation

# Démonstration complète

---gcc -Wall -O2 demo_injection.c syscalls_indirect.c -o demo_injection.exe -lntdll -s

```

## 📂 Structure du Projet

---

```

edr-evasion-syscalls/## 📝 Utilisation

│

├── 📄 README.md                    ← Ce fichier### 1. Lire le cours théorique

├── 📄 LICENSE                      ← Licence MIT

├── 📄 DISCLAIMER.md                ← Avertissements légauxOuvrez `COURS_SYSCALLS_EDR.md` pour comprendre les concepts.

├── 📄 .gitignore                   ← Fichiers à exclure

│### 2. Étudier le code commenté

├── 📁 Docu_theorique/              ← Documentation théorique

│   ├── COURS_SYSCALLS_EDR.md      ← Cours principal (théorie complète)Chaque fichier `.c` contient des commentaires détaillés expliquant :

│   ├── SCHEMAS_VISUELS.md         ← Diagrammes et schémas- 🎯 Le principe de chaque technique

│   ├── INDEX.md                   ← Navigation du cours- ⚙️ Comment le code fonctionne

│   └── GUIDE_SYSWHISPERS.md       ← Guide d'utilisation de SysWhispers- ⚠️ Les points de détection EDR

│- 💡 Les bonnes pratiques

├── 📁 Code_source/                 ← Implémentations C

│   ├── syscalls.h                 ← Structures et prototypes### 3. Compiler et tester

│   ├── syscalls_direct.c          ← Syscalls directs (~450 lignes)

│   ├── syscalls_indirect.c        ← Syscalls indirects (~800 lignes)```bash

│   └── demo_injection.c           ← Démo d'injection complète# Compilation

│make all

├── 📁 Exo/                         ← Exercices pratiques

│   └── EXERCICES_PRATIQUES.md     ← 12 exercices progressifs# Test de la démonstration complète

│./demo_injection.exe

└── 📁 Outils_scripts/              ← Scripts et outils```

    └── README.md                   ← Guide des outils

```### 4. Analyser les résultats



---Le programme affiche chaque étape en détail :

```

## 🔧 Prérequis╔══════════════════════════════════════════════════════╗

║       INJECTION DE SHELLCODE - ÉTAPES DÉTAILLÉES    ║

### Système d'Exploitation╚══════════════════════════════════════════════════════╝

- **Windows 10** ou **Windows 11** (x64)

- Machine virtuelle recommandée pour les tests┌─────────────────────────────────────────────────────┐

│ ÉTAPE 1 : Allocation mémoire                        │

### Outils de Développement└─────────────────────────────────────────────────────┘

- **GCC** (MinGW-w64) ou **MSVC**  • Protection : PAGE_READWRITE (pas RWX !)

- **Make** (optionnel)  • Taille     : 256 bytes

- Éditeur de code (VS Code recommandé)  • Méthode    : NtAllocateVirtualMemory (indirect)



### Connaissances Recommandées  ✓ Allocation réussie

- Bases du langage C    └─> Adresse : 0x0000020A12340000

- Notions d'architecture Windows    └─> Taille  : 4096 bytes

- Compréhension basique des appels système...

```

---

---

## 💻 Installation

## 🔬 Détails Techniques

### 1. Cloner le Dépôt

### Syscalls Directs

```bash

git clone https://github.com/VOTRE_USERNAME/edr-evasion-syscalls.git**Principe** : Exécuter directement l'instruction `syscall` sans passer par `ntdll.dll`.

cd edr-evasion-syscalls

```**Avantages** :

- ✅ Bypass des hooks EDR

### 2. Installer GCC (MinGW-w64)- ✅ Simple à implémenter



#### Via MSYS2 (Recommandé)**Inconvénients** :

- ❌ Instruction `syscall` détectable dans notre code

```bash- ❌ SSN hardcodés (différents selon Windows version)

# Télécharger et installer MSYS2 depuis https://www.msys2.org/

**Code clé** :

# Ouvrir MSYS2 et installer GCC```c

pacman -Syu__asm__ volatile (

pacman -S mingw-w64-x86_64-gcc make    "mov r10, rcx\n"

```    "mov eax, 0x18\n"    // SSN de NtAllocateVirtualMemory

    "syscall\n"           // ⚠️ Instruction détectable

#### Ajouter au PATH    "ret\n"

);

``````

C:\msys64\mingw64\bin

```### Syscalls Indirects



### 3. Vérifier l'Installation**Principe** : Réutiliser l'instruction `syscall` qui existe déjà dans `ntdll.dll`.



```bash**Avantages** :

gcc --version- ✅ Pas d'instruction `syscall` dans notre code

make --version- ✅ Call stack légitime (via ntdll)

```- ✅ SSN extraits dynamiquement

- ✅ Plus difficile à détecter

---

**Inconvénients** :

## 🚀 Utilisation- ❌ Plus complexe à implémenter

- ❌ Parsing PE nécessaire

### Compilation

**Processus** :

#### Avec Make (Recommandé)1. Charger ntdll.dll fraîche depuis le disque

2. Parser le PE pour trouver les fonctions

```bash3. Extraire les SSN des fonctions

cd Code_source4. Trouver une instruction `syscall; ret`

make5. Jump vers cette instruction au lieu d'exécuter notre propre syscall

```

**Code clé** :

#### Compilation Manuelle```c

// Au lieu de : syscall

**Syscalls Directs:**// On fait :

```bash__asm__ volatile (

gcc -o syscalls_direct.exe syscalls_direct.c -lntdll    "mov r10, rcx\n"

```    "mov eax, %0\n"      // SSN extrait dynamiquement

    "jmp %1\n"           // Jump vers syscall dans ntdll

**Syscalls Indirects:**    :: "r"(ssn), "r"(syscallAddress)

```bash);

gcc -o syscalls_indirect.exe syscalls_indirect.c -lntdll```

```

---

**Démo d'Injection:**

```bash## 🛡️ Détection EDR

gcc -o demo_injection.exe demo_injection.c syscalls_indirect.c -lntdll

```### Ce que les EDR voient



### Exécution| Technique | Hook NTDLL | Instruction Syscall | Call Stack | Détection |

|-----------|-----------|---------------------|------------|-----------|

⚠️ **Lancez toujours avec les droits administrateur**| **API Win32** | ✅ Oui | ❌ Non | Normale | 🔴 Haute |

| **Syscalls Directs** | ❌ Non | ✅ Oui | Anormale | 🟡 Moyenne |

```bash| **Syscalls Indirects** | ❌ Non | ❌ Non | Normale | 🟢 Faible |

# Tester les syscalls directs

.\syscalls_direct.exe### Contre-mesures EDR modernes



# Tester les syscalls indirectsLes EDR avancés utilisent :

.\syscalls_indirect.exe

1. **ETW (Event Tracing for Windows)**

# Tester l'injection (dans une VM isolée!)   - Surveillance au niveau kernel

.\demo_injection.exe   - Détection des allocations RWX

```   - Solution : Allouer RW → Écrire → Changer RX



---2. **Kernel Callbacks**

   - Interception des opérations sensibles

## 📚 Contenu Pédagogique   - PsSetCreateThreadNotifyRoutine

   - Solution : Thread hijacking, APC injection

### 1. Cours Théorique

3. **Stack Walking**

**[COURS_SYSCALLS_EDR.md](Docu_theorique/COURS_SYSCALLS_EDR.md)**   - Vérification de la call stack

- Architecture Windows (User Mode / Kernel Mode)   - Détection de return address anormales

- Fonctionnement des syscalls   - Solution : Syscalls indirects (stack propre)

- Mécanismes EDR et techniques de hooking

- Comparaison syscalls directs vs indirects4. **Analyse Comportementale**

- Techniques de détection et contournement   - Pattern matching : Alloc → Write → Protect → Execute

   - Solution : Sleep obfuscation, délais aléatoires

### 2. Schémas Visuels

---

**[SCHEMAS_VISUELS.md](Docu_theorique/SCHEMAS_VISUELS.md)**

- Diagrammes de flux d'exécution## 📚 Ressources Supplémentaires

- Schémas d'architecture

- Visualisation des hooks### Outils Utiles

- Parsing du format PE

- **SysWhispers2** : Génère automatiquement du code pour syscalls

### 3. Guide SysWhispers  - `tools/SysWhispers/syswhispers.py`

  - https://github.com/jthuraisamy/SysWhispers2

**[GUIDE_SYSWHISPERS.md](Docu_theorique/GUIDE_SYSWHISPERS.md)**

- Installation et configuration- **PE-bear** : Analyse de fichiers PE

- Génération de stubs syscall- **x64dbg** : Débogueur pour analyser ntdll.dll

- Intégration dans vos projets- **Process Hacker** : Surveillance des processus



### 4. Exercices Pratiques### Lectures Recommandées



**[EXERCICES_PRATIQUES.md](Exo/EXERCICES_PRATIQUES.md)**1. **Windows Internals** (Mark Russinovich)

- 12 exercices progressifs   - Architecture Windows en profondeur

- Du niveau débutant au niveau expert   - Gestion de la mémoire et des processus

- Solutions et explications détaillées

2. **Red Team Development and Operations** (Joe Vest)

---   - Techniques offensives modernes

   - Évasion EDR/AV

## 💡 Exemples

3. **Blogs et Articles**

### Exemple 1: Syscall Direct   - https://www.mdsec.co.uk/

   - https://blog.malwarebytes.com/

```c   - https://www.ired.team/

#include "syscalls.h"

### Vidéos et Conférences

// Allouer de la mémoire avec NtAllocateVirtualMemory (direct)

PVOID baseAddress = NULL;- **DEFCON** : Talks sur le bypass EDR

SIZE_T regionSize = 0x1000;- **Black Hat** : Présentations techniques

NTSTATUS status;- **YouTube** : Chaînes red team (MalDev Academy, etc.)



status = NtAllocateVirtualMemory_Direct(---

    GetCurrentProcess(),

    &baseAddress,## ⚠️ Avertissement Légal

    0,

    &regionSize,```

    MEM_COMMIT | MEM_RESERVE,╔══════════════════════════════════════════════════════╗

    PAGE_READWRITE║               ⚠️  AVERTISSEMENT                      ║

);╚══════════════════════════════════════════════════════╝



if (NT_SUCCESS(status)) {Ce code est fourni à des fins ÉDUCATIVES UNIQUEMENT.

    printf("[+] Mémoire allouée à: 0x%p\n", baseAddress);

}L'utilisation de ces techniques sur des systèmes sans

```autorisation explicite est ILLÉGALE et peut entraîner :

  • Des poursuites judiciaires

### Exemple 2: Syscall Indirect  • Des amendes importantes

  • Des peines de prison

```c

#include "syscalls.h"L'auteur décline toute responsabilité pour un usage

malveillant de ce code.

// Initialiser les syscalls indirects

if (!InitializeIndirectSyscalls()) {UTILISEZ UNIQUEMENT dans un environnement de test

    printf("[-] Échec de l'initialisation\n");contrôlé avec autorisation appropriée.

    return 1;```

}

---

// Utiliser NtAllocateVirtualMemory (indirect)

PVOID baseAddress = NULL;## 🧪 Environnement de Test

SIZE_T regionSize = 0x1000;

### Recommandations

NTSTATUS status = NtAllocateVirtualMemory_Indirect(

    GetCurrentProcess(),Pour tester ces techniques en toute sécurité :

    &baseAddress,

    0,1. **Machine Virtuelle isolée**

    &regionSize,   - VMware Workstation / VirtualBox

    MEM_COMMIT | MEM_RESERVE,   - Windows 10/11 x64

    PAGE_READWRITE   - Pas de connexion réseau

);

```2. **Antivirus de test**

   - Windows Defender (inclus)

### Exemple 3: Injection de Processus   - Autre EDR gratuit (Sophos Home, etc.)

   - Observer les détections

```c

// Voir demo_injection.c pour l'exemple complet3. **Outils de monitoring**

// Pipeline: Allouer → Écrire → Protéger → Créer Thread   - Process Monitor (Sysinternals)

```   - Process Hacker

   - API Monitor

---

### Scénarios de Test

## 🤝 Contribution

```bash

Les contributions sont les bienvenues! Voici comment contribuer:# Test 1 : Exécution basique

./demo_injection.exe

1. **Fork** le projet

2. Créez une branche pour votre fonctionnalité (`git checkout -b feature/nouvelle-technique`)# Test 2 : Avec Process Monitor actif

3. Committez vos changements (`git commit -m 'Ajout d'une nouvelle technique'`)# Observer les appels système

4. Poussez vers la branche (`git push origin feature/nouvelle-technique`)

5. Ouvrez une **Pull Request**# Test 3 : Avec Windows Defender actif

# Vérifier si détecté ou non

### Suggestions de Contributions

# Test 4 : Analyse du binaire

- 📝 Amélioration de la documentation# Utiliser pestudio, PE-bear, etc.

- 🐛 Correction de bugs```

- ✨ Nouvelles techniques d'évasion

- 🧪 Nouveaux exercices pratiques---

- 🌍 Traductions (anglais, espagnol, etc.)

- 📊 Benchmarks et tests de performance## 🔧 Dépannage



---### Erreur : "Failed to initialize indirect syscalls"



## 📜 Licence**Cause** : Impossible de lire ntdll.dll



Ce projet est sous licence **MIT**. Voir le fichier [LICENSE](LICENSE) pour plus de détails.**Solution** :

```bash

```# Vérifier les permissions

MIT Licenseicacls C:\Windows\System32\ntdll.dll



Copyright (c) 2025 28zaaakypro@proton.me# Exécuter en administrateur

```

Permission is hereby granted, free of charge, to any person obtaining a copy

of this software and associated documentation files (the "Software"), to deal### Erreur : "Failed to find syscall instruction"

in the Software without restriction, including without limitation the rights

to use, copy, modify, merge, publish, distribute, sublicense, and/or sell**Cause** : Version de Windows non supportée

copies of the Software, and to permit persons to whom the Software is

furnished to do so, subject to the following conditions:**Solution** :

```c

[...]// Modifier la recherche dans FindSyscallAddress()

```// Chercher d'autres patterns : 0F 05 (sans C3)

```

---

### Erreur de compilation : "undefined reference to 'DoSyscall'"

## 📖 Ressources

**Cause** : L'assembleur inline n'est pas compilé correctement

### Documentation Microsoft

**Solution** :

- [Windows Syscalls](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-nt-and-zw-versions-of-the-native-system-services-routines)```bash

- [PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)# Compiler avec l'option -masm=intel

- [NTDLL.dll](https://en.wikipedia.org/wiki/Microsoft_Windows_library_files#NTDLL.DLL)gcc -masm=intel syscalls_direct.c -o syscalls_direct.exe

```

### Outils Complémentaires

---

- [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2) - Génération automatique de stubs

- [Process Hacker](https://processhacker.sourceforge.io/) - Analyse de processus## 📊 Comparaison des Techniques

- [x64dbg](https://x64dbg.com/) - Débogueur Windows

### Performance

### Articles et Recherches

| Technique | Vitesse | Furtivité | Complexité |

- [MDSec: Bypassing EDR](https://www.mdsec.co.uk/knowledge-centre/insights/)|-----------|---------|-----------|------------|

- [Red Team Notes](https://www.ired.team/)| API Win32 | 🟢 Rapide | 🔴 Faible | 🟢 Simple |

- [MalDev Academy](https://maldevacademy.com/)| Syscalls Directs | 🟢 Rapide | 🟡 Moyenne | 🟡 Moyenne |

| Syscalls Indirects | 🟡 Moyenne | 🟢 Haute | 🔴 Complexe |

### Projets Similaires

### Compatibilité

- [Malware Development](https://github.com/topics/malware-development)

- [EDR Bypass](https://github.com/topics/edr-bypass)| Windows Version | Syscalls Directs | Syscalls Indirects |

- [Windows Internals](https://github.com/topics/windows-internals)|-----------------|------------------|-------------------|

| Windows 10 1507-1607 | ✅ SSN différents | ✅ Auto-détection |

---| Windows 10 1703-1909 | ✅ SSN différents | ✅ Auto-détection |

| Windows 10 2004+ | ✅ SSN différents | ✅ Auto-détection |

## 🎓 Parcours d'Apprentissage| Windows 11 | ✅ SSN différents | ✅ Auto-détection |



### Niveau 1: Débutant (2-4 heures)---

1. Lire le cours théorique complet

2. Comprendre l'architecture Windows## 🎓 Exercices Pratiques

3. Étudier les schémas visuels

4. Compiler et exécuter les exemples### Exercice 1 : Modifier le shellcode



### Niveau 2: Intermédiaire (4-8 heures)Remplacez le shellcode de démonstration par un vrai shellcode :

1. Analyser le code des syscalls directs

2. Comprendre le parsing PE```bash

3. Étudier les syscalls indirects# Générer un shellcode avec msfvenom

4. Faire les exercices 1-6msfvenom -p windows/x64/exec CMD=calc.exe -f c



### Niveau 3: Avancé (8-16 heures)# L'intégrer dans demo_injection.c

1. Implémenter vos propres syscalls```

2. Modifier le code d'injection

3. Faire les exercices 7-12### Exercice 2 : Injection dans un processus distant

4. Tester contre Windows Defender

Modifiez le code pour injecter dans un autre processus :

### Niveau 4: Expert (16+ heures)

1. Développer de nouvelles techniques```c

2. Tester contre des EDR commerciaux// Au lieu de GetCurrentProcess()

3. Contribuer au projetHANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);

4. Créer vos propres outils```



---### Exercice 3 : Ajouter du chiffrement



## 🏆 RemerciementsChiffrez le shellcode avec XOR/RC4 avant injection :



- **Microsoft** pour la documentation Windows Internals```c

- **MDSec** pour leurs recherches sur l'évasion EDR// Chiffrer

- **@jthuraisamy** pour SysWhispersfor (size_t i = 0; i < size; i++) {

- **La communauté Red Team** pour le partage de connaissances    shellcode[i] ^= 0xAA;

- Tous les contributeurs de ce projet}



---// Déchiffrer après écriture

for (size_t i = 0; i < size; i++) {

## 📞 Contact    ((unsigned char*)baseAddress)[i] ^= 0xAA;

}

Pour toute question ou suggestion:```



- 📧 Email: 28zaaakypro@proton.me### Exercice 4 : Extraire les SSN dynamiquement

- 🐛 Issues: [GitHub Issues](https://github.com/VOTRE_USERNAME/edr-evasion-syscalls/issues)

- 💬 Discussions: [GitHub Discussions](https://github.com/VOTRE_USERNAME/edr-evasion-syscalls/discussions)Au lieu de hardcoder les SSN, extraire dynamiquement pour chaque version Windows.



------



## ⭐ Soutenir le Projet## 📞 Support et Contribution



Si ce projet vous a été utile:Pour toute question ou amélioration :



- ⭐ **Star** le dépôt1. Lisez d'abord le cours théorique

- 🔄 **Fork** et contribuez2. Vérifiez les commentaires dans le code

- 📢 **Partagez** avec la communauté3. Testez dans un environnement isolé

- 📝 **Écrivez** un article ou tutoriel4. Documentez vos modifications



------



<div align="center">## 📜 Changelog



**Développé avec ❤️ pour la communauté de sécurité offensive**### Version 1.0 (2025-11-10)

- ✅ Cours théorique complet

📚 **Apprenez** | 🛡️ **Défendez** | 🎓 **Partagez**- ✅ Implémentation syscalls directs

- ✅ Implémentation syscalls indirects

---- ✅ Démonstration d'injection

- ✅ Makefile pour compilation

*Dernière mise à jour: 2025*- ✅ Documentation complète



</div>---


## 📖 Licence

Ce projet est à des fins éducatives uniquement. Aucune garantie n'est fournie.

**Utilisez de manière responsable et éthique.**

---

Bon apprentissage ! 🚀🛡️
