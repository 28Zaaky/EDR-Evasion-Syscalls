# 📚 SYSCALLS DIRECTS ET INDIRECTS - Guide Pratique

## 📖 Introduction

Ce projet contient un **cours complet** et des **implémentations pratiques** sur les syscalls directs et indirects pour l'évasion EDR (Endpoint Detection and Response).

### 📁 Contenu du dossier

```
Evasion/
├── COURS_SYSCALLS_EDR.md      # Cours théorique complet
├── syscalls.h                  # Header avec structures et prototypes
├── syscalls_direct.c           # Implémentation syscalls directs
├── syscalls_indirect.c         # Implémentation syscalls indirects
├── demo_injection.c            # Démonstration pratique complète
├── Makefile                    # Compilation automatique
└── README.md                   # Ce fichier
```

---

## 🎯 Objectifs Pédagogiques

### Partie Théorique
✅ Comprendre l'architecture User Mode / Kernel Mode  
✅ Comprendre comment fonctionnent les EDR et leurs hooks  
✅ Apprendre les différences entre syscalls directs et indirects  
✅ Connaître les techniques de détection et contre-mesures  

### Partie Pratique
✅ Implémenter des syscalls directs en C + ASM  
✅ Implémenter des syscalls indirects (plus furtifs)  
✅ Parser le format PE pour extraire les SSN  
✅ Réaliser une injection de shellcode complète  

---

## 🚀 Compilation

### Prérequis

- **GCC** (MinGW-w64 sur Windows)
- **Windows 10/11** x64
- Droits administrateur (pour certaines opérations)

### Compilation Simple

```bash
# Compiler tous les programmes
make all

# Compiler uniquement une cible spécifique
make direct      # Syscalls directs
make indirect    # Syscalls indirects
make demo        # Démonstration complète

# Nettoyer les fichiers compilés
make clean
```

### Compilation Manuelle

Si vous n'avez pas `make` :

```bash
# Syscalls directs
gcc -Wall -O2 -DCOMPILE_DEMO_DIRECT syscalls_direct.c -o syscalls_direct.exe -lntdll -s

# Syscalls indirects
gcc -Wall -O2 -DCOMPILE_DEMO_INDIRECT syscalls_indirect.c -o syscalls_indirect.exe -lntdll -s

# Démonstration complète
gcc -Wall -O2 demo_injection.c syscalls_indirect.c -o demo_injection.exe -lntdll -s
```

---

## 📝 Utilisation

### 1. Lire le cours théorique

Ouvrez `COURS_SYSCALLS_EDR.md` pour comprendre les concepts.

### 2. Étudier le code commenté

Chaque fichier `.c` contient des commentaires détaillés expliquant :
- 🎯 Le principe de chaque technique
- ⚙️ Comment le code fonctionne
- ⚠️ Les points de détection EDR
- 💡 Les bonnes pratiques

### 3. Compiler et tester

```bash
# Compilation
make all

# Test de la démonstration complète
./demo_injection.exe
```

### 4. Analyser les résultats

Le programme affiche chaque étape en détail :
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

## 🔬 Détails Techniques

### Syscalls Directs

**Principe** : Exécuter directement l'instruction `syscall` sans passer par `ntdll.dll`.

**Avantages** :
- ✅ Bypass des hooks EDR
- ✅ Simple à implémenter

**Inconvénients** :
- ❌ Instruction `syscall` détectable dans notre code
- ❌ SSN hardcodés (différents selon Windows version)

**Code clé** :
```c
__asm__ volatile (
    "mov r10, rcx\n"
    "mov eax, 0x18\n"    // SSN de NtAllocateVirtualMemory
    "syscall\n"           // ⚠️ Instruction détectable
    "ret\n"
);
```

### Syscalls Indirects

**Principe** : Réutiliser l'instruction `syscall` qui existe déjà dans `ntdll.dll`.

**Avantages** :
- ✅ Pas d'instruction `syscall` dans notre code
- ✅ Call stack légitime (via ntdll)
- ✅ SSN extraits dynamiquement
- ✅ Plus difficile à détecter

**Inconvénients** :
- ❌ Plus complexe à implémenter
- ❌ Parsing PE nécessaire

**Processus** :
1. Charger ntdll.dll fraîche depuis le disque
2. Parser le PE pour trouver les fonctions
3. Extraire les SSN des fonctions
4. Trouver une instruction `syscall; ret`
5. Jump vers cette instruction au lieu d'exécuter notre propre syscall

**Code clé** :
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

### Ce que les EDR voient

| Technique | Hook NTDLL | Instruction Syscall | Call Stack | Détection |
|-----------|-----------|---------------------|------------|-----------|
| **API Win32** | ✅ Oui | ❌ Non | Normale | 🔴 Haute |
| **Syscalls Directs** | ❌ Non | ✅ Oui | Anormale | 🟡 Moyenne |
| **Syscalls Indirects** | ❌ Non | ❌ Non | Normale | 🟢 Faible |

### Contre-mesures EDR modernes

Les EDR avancés utilisent :

1. **ETW (Event Tracing for Windows)**
   - Surveillance au niveau kernel
   - Détection des allocations RWX
   - Solution : Allouer RW → Écrire → Changer RX

2. **Kernel Callbacks**
   - Interception des opérations sensibles
   - PsSetCreateThreadNotifyRoutine
   - Solution : Thread hijacking, APC injection

3. **Stack Walking**
   - Vérification de la call stack
   - Détection de return address anormales
   - Solution : Syscalls indirects (stack propre)

4. **Analyse Comportementale**
   - Pattern matching : Alloc → Write → Protect → Execute
   - Solution : Sleep obfuscation, délais aléatoires

---

## 📚 Ressources Supplémentaires

### Outils Utiles

- **SysWhispers2** : Génère automatiquement du code pour syscalls
  - `tools/SysWhispers/syswhispers.py`
  - https://github.com/jthuraisamy/SysWhispers2

- **PE-bear** : Analyse de fichiers PE
- **x64dbg** : Débogueur pour analyser ntdll.dll
- **Process Hacker** : Surveillance des processus

### Lectures Recommandées

1. **Windows Internals** (Mark Russinovich)
   - Architecture Windows en profondeur
   - Gestion de la mémoire et des processus

2. **Red Team Development and Operations** (Joe Vest)
   - Techniques offensives modernes
   - Évasion EDR/AV

3. **Blogs et Articles**
   - https://www.mdsec.co.uk/
   - https://blog.malwarebytes.com/
   - https://www.ired.team/

### Vidéos et Conférences

- **DEFCON** : Talks sur le bypass EDR
- **Black Hat** : Présentations techniques
- **YouTube** : Chaînes red team (MalDev Academy, etc.)

---

## ⚠️ Avertissement Légal

```
╔══════════════════════════════════════════════════════╗
║               ⚠️  AVERTISSEMENT                      ║
╚══════════════════════════════════════════════════════╝

Ce code est fourni à des fins ÉDUCATIVES UNIQUEMENT.

L'utilisation de ces techniques sur des systèmes sans
autorisation explicite est ILLÉGALE et peut entraîner :
  • Des poursuites judiciaires
  • Des amendes importantes
  • Des peines de prison

L'auteur décline toute responsabilité pour un usage
malveillant de ce code.

UTILISEZ UNIQUEMENT dans un environnement de test
contrôlé avec autorisation appropriée.
```

---

## 🧪 Environnement de Test

### Recommandations

Pour tester ces techniques en toute sécurité :

1. **Machine Virtuelle isolée**
   - VMware Workstation / VirtualBox
   - Windows 10/11 x64
   - Pas de connexion réseau

2. **Antivirus de test**
   - Windows Defender (inclus)
   - Autre EDR gratuit (Sophos Home, etc.)
   - Observer les détections

3. **Outils de monitoring**
   - Process Monitor (Sysinternals)
   - Process Hacker
   - API Monitor

### Scénarios de Test

```bash
# Test 1 : Exécution basique
./demo_injection.exe

# Test 2 : Avec Process Monitor actif
# Observer les appels système

# Test 3 : Avec Windows Defender actif
# Vérifier si détecté ou non

# Test 4 : Analyse du binaire
# Utiliser pestudio, PE-bear, etc.
```

---

## 🔧 Dépannage

### Erreur : "Failed to initialize indirect syscalls"

**Cause** : Impossible de lire ntdll.dll

**Solution** :
```bash
# Vérifier les permissions
icacls C:\Windows\System32\ntdll.dll

# Exécuter en administrateur
```

### Erreur : "Failed to find syscall instruction"

**Cause** : Version de Windows non supportée

**Solution** :
```c
// Modifier la recherche dans FindSyscallAddress()
// Chercher d'autres patterns : 0F 05 (sans C3)
```

### Erreur de compilation : "undefined reference to 'DoSyscall'"

**Cause** : L'assembleur inline n'est pas compilé correctement

**Solution** :
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

## 🎓 Exercices Pratiques

### Exercice 1 : Modifier le shellcode

Remplacez le shellcode de démonstration par un vrai shellcode :

```bash
# Générer un shellcode avec msfvenom
msfvenom -p windows/x64/exec CMD=calc.exe -f c

# L'intégrer dans demo_injection.c
```

### Exercice 2 : Injection dans un processus distant

Modifiez le code pour injecter dans un autre processus :

```c
// Au lieu de GetCurrentProcess()
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
```

### Exercice 3 : Ajouter du chiffrement

Chiffrez le shellcode avec XOR/RC4 avant injection :

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

### Exercice 4 : Extraire les SSN dynamiquement

Au lieu de hardcoder les SSN, extraire dynamiquement pour chaque version Windows.

---

## 📞 Support et Contribution

Pour toute question ou amélioration :

1. Lisez d'abord le cours théorique
2. Vérifiez les commentaires dans le code
3. Testez dans un environnement isolé
4. Documentez vos modifications

---

## 📜 Changelog

### Version 1.0 (2025-11-10)
- ✅ Cours théorique complet
- ✅ Implémentation syscalls directs
- ✅ Implémentation syscalls indirects
- ✅ Démonstration d'injection
- ✅ Makefile pour compilation
- ✅ Documentation complète

---

## 📖 Licence

Ce projet est à des fins éducatives uniquement. Aucune garantie n'est fournie.

**Utilisez de manière responsable et éthique.**

---

Bon apprentissage ! 🚀🛡️
