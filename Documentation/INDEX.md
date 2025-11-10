# 📑 INDEX DU COURS - SYSCALLS ET ÉVASION EDR

Bienvenue dans ce cours complet sur les syscalls directs et indirects !

---

## 📚 Plan du Cours

### 1️⃣ Documentation Théorique

| Fichier | Description | Temps de lecture |
|---------|-------------|------------------|
| **COURS_SYSCALLS_EDR.md** | Cours théorique complet sur les syscalls et EDR | 45 min |
| **SCHEMAS_VISUELS.md** | Schémas et diagrammes pour visualiser les concepts | 30 min |
| **GUIDE_SYSWHISPERS.md** | Guide d'utilisation de l'outil SysWhispers | 15 min |

### 2️⃣ Code Source

| Fichier | Description | Lignes |
|---------|-------------|--------|
| **syscalls.h** | Header avec structures et prototypes | 150 |
| **syscalls_direct.c** | Implémentation syscalls directs + démo | 450 |
| **syscalls_indirect.c** | Implémentation syscalls indirects + démo | 800 |
| **demo_injection.c** | Démonstration complète d'injection | 400 |

### 3️⃣ Outils et Scripts

| Fichier | Description | Type |
|---------|-------------|------|
| **Makefile** | Compilation automatique (Linux/Mac) | Makefile |
| **compile.bat** | Script de compilation (Windows) | Batch |

### 4️⃣ Guides Pratiques

| Fichier | Description | Niveau |
|---------|-------------|--------|
| **README.md** | Guide complet d'utilisation du projet | Tous |
| **EXERCICES_PRATIQUES.md** | Exercices progressifs avec solutions | Débutant → Expert |

---

## 🎯 Parcours d'Apprentissage Recommandé

### 📖 Phase 1 : Théorie (2-3 heures)

```
1. Lire COURS_SYSCALLS_EDR.md
   └─> Comprendre l'architecture Windows
   └─> Comprendre le fonctionnement des EDR
   └─> Différences syscalls directs vs indirects

2. Consulter SCHEMAS_VISUELS.md
   └─> Visualiser les flux d'appels
   └─> Comprendre les layers de détection
   └─> Mémoriser l'architecture mémoire

3. Parcourir GUIDE_SYSWHISPERS.md
   └─> Découvrir l'outil SysWhispers
   └─> Comprendre la génération automatique
```

### 💻 Phase 2 : Pratique (3-4 heures)

```
1. Compiler les démonstrations
   └─> Windows : compile.bat
   └─> Linux/Mac : make all

2. Étudier le code commenté
   └─> syscalls_direct.c
   └─> syscalls_indirect.c
   └─> demo_injection.c

3. Exécuter les démonstrations
   └─> Comprendre le flux d'exécution
   └─> Observer les logs détaillés
   └─> Analyser avec Process Monitor

4. Déboguer avec x64dbg
   └─> Placer des breakpoints
   └─> Observer les registres
   └─> Suivre le flow assembleur
```

### 🔬 Phase 3 : Expérimentation (4-6 heures)

```
1. Exercices débutant (EXERCICES_PRATIQUES.md)
   └─> Modifier le shellcode
   └─> Ajouter des logs
   └─> Tester avec Windows Defender

2. Exercices intermédiaire
   └─> Injection processus distant
   └─> Chiffrement shellcode
   └─> Ajouter de nouveaux syscalls

3. Exercices avancés
   └─> Hell's Gate / Halo's Gate
   └─> Sleep obfuscation
   └─> Unhooking NTDLL

4. Exercices expert
   └─> Module stomping
   └─> Bypass ETW
   └─> Syscall randomizer
```

### 🏗️ Phase 4 : Projet Final (8-10 heures)

```
Créer un loader complet combinant toutes les techniques
└─> Voir la section "Projet Final" dans EXERCICES_PRATIQUES.md
```

---

## 🗂️ Structure Complète du Dossier

```
01_Projects/Evasion/
│
├── 📖 Documentation Théorique
│   ├── COURS_SYSCALLS_EDR.md          ← Cours complet
│   ├── SCHEMAS_VISUELS.md             ← Diagrammes
│   ├── GUIDE_SYSWHISPERS.md           ← Guide SysWhispers
│   └── INDEX.md                        ← Ce fichier
│
├── 💻 Code Source
│   ├── syscalls.h                      ← Header principal
│   ├── syscalls_direct.c               ← Syscalls directs
│   ├── syscalls_indirect.c             ← Syscalls indirects
│   └── demo_injection.c                ← Démo complète
│
├── 🔧 Outils et Scripts
│   ├── Makefile                        ← Compilation Unix
│   ├── compile.bat                     ← Compilation Windows
│   └── README.md                       ← Guide utilisateur
│
├── 📝 Guides Pratiques
│   └── EXERCICES_PRATIQUES.md         ← Exercices progressifs
│
└── 🎯 Fichiers de Travail
    ├── Evasion_poc.c                   ← POC initial
    ├── Evasion_poc_obf.c               ← POC obfusqué
    ├── gen_obf_header.py               ← Script obfuscation
    └── obf_strings.h                   ← Strings obfusquées
```

---

## 📊 Contenu par Niveau

### 🟢 Niveau Débutant

**Objectif** : Comprendre les bases

**Fichiers à lire** :
- ✅ COURS_SYSCALLS_EDR.md (Sections 1.1 à 1.3)
- ✅ SCHEMAS_VISUELS.md (Section 1)
- ✅ README.md

**Code à étudier** :
- ✅ syscalls.h (structures)
- ✅ syscalls_direct.c (fonctions simples)

**Exercices** :
- ✅ Exercices 1 à 3 (EXERCICES_PRATIQUES.md)

**Durée estimée** : 4-6 heures

---

### 🟡 Niveau Intermédiaire

**Objectif** : Maîtriser les techniques de base

**Fichiers à lire** :
- ✅ COURS_SYSCALLS_EDR.md (Sections 1.4 à 1.5)
- ✅ SCHEMAS_VISUELS.md (Sections 2 et 3)
- ✅ GUIDE_SYSWHISPERS.md

**Code à étudier** :
- ✅ syscalls_indirect.c (parsing PE)
- ✅ demo_injection.c (flow complet)

**Exercices** :
- ✅ Exercices 4 à 6 (EXERCICES_PRATIQUES.md)

**Durée estimée** : 8-10 heures

---

### 🟠 Niveau Avancé

**Objectif** : Techniques d'évasion avancées

**Fichiers à lire** :
- ✅ COURS_SYSCALLS_EDR.md (Section 1.5 complète)
- ✅ SCHEMAS_VISUELS.md (Sections 4, 5, 6)

**Code à étudier** :
- ✅ Tous les fichiers en profondeur
- ✅ Code assembleur inline

**Exercices** :
- ✅ Exercices 7 à 9 (EXERCICES_PRATIQUES.md)

**Durée estimée** : 12-15 heures

---

### 🔴 Niveau Expert

**Objectif** : Maîtrise complète et création d'outils

**Fichiers à lire** :
- ✅ Tous les documents
- ✅ Code source de SysWhispers

**Code à étudier** :
- ✅ Analyse de malwares réels
- ✅ Code de projets open source (Cobalt Strike, etc.)

**Exercices** :
- ✅ Exercices 10 à 12 (EXERCICES_PRATIQUES.md)
- ✅ Projet final

**Durée estimée** : 20+ heures

---

## 🎓 Compétences Acquises

À la fin de ce cours, vous serez capable de :

### Connaissances Théoriques
- ✅ Expliquer l'architecture Windows (User Mode / Kernel Mode)
- ✅ Comprendre le fonctionnement des EDR et leurs techniques de détection
- ✅ Différencier les syscalls directs, indirects et API normales
- ✅ Connaître les contre-mesures EDR (ETW, Callbacks, etc.)

### Compétences Pratiques
- ✅ Implémenter des syscalls directs en C + ASM
- ✅ Parser le format PE pour extraire des informations
- ✅ Créer des syscalls indirects pour bypasser les hooks
- ✅ Injecter du shellcode de manière furtive
- ✅ Chiffrer/déchiffrer du shellcode
- ✅ Manipuler la mémoire de processus distants

### Techniques Avancées
- ✅ Unhooking NTDLL
- ✅ Hell's Gate / Halo's Gate
- ✅ Module Stomping
- ✅ Sleep Obfuscation
- ✅ Bypass ETW
- ✅ Randomisation de syscalls

---

## 🔗 Ressources Externes

### Outils
- [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2)
- [x64dbg](https://x64dbg.com/)
- [Process Hacker](https://processhacker.sourceforge.io/)
- [PE-bear](https://github.com/hasherezade/pe-bear)

### Lectures
- Windows Internals (Microsoft Press)
- Red Team Development and Operations
- Malware Analysis Book

### Sites Web
- https://www.mdsec.co.uk/knowledge-centre/
- https://www.ired.team/
- https://maldevacademy.com/

### Vidéos
- DEFCON talks sur EDR bypass
- Black Hat présentations
- YouTube: MalDev Academy

---

## ⚠️ Avertissements Importants

### Légal
```
╔══════════════════════════════════════════════════════╗
║               ⚠️  ATTENTION LÉGALE                   ║
╚══════════════════════════════════════════════════════╝

Ces techniques sont fournies à des fins ÉDUCATIVES.

L'utilisation malveillante ou non autorisée de ces
techniques est ILLÉGALE et peut entraîner :
  • Poursuites judiciaires
  • Amendes importantes
  • Peines d'emprisonnement

Utilisez UNIQUEMENT dans un environnement de test
contrôlé avec autorisation appropriée.
```

### Sécurité
- ✅ Toujours tester dans une VM isolée
- ✅ Ne jamais exécuter sur un système de production
- ✅ Désactiver la connexion réseau pendant les tests
- ✅ Sauvegarder vos VMs avant les tests

---

## 🆘 Support et Dépannage

### Problèmes Courants

**Erreur de compilation** :
```bash
# Vérifier que GCC est installé
gcc --version

# Installer sur Windows (MSYS2)
pacman -S mingw-w64-x86_64-gcc
```

**Programme ne démarre pas** :
- Vérifier les privilèges (exécuter en admin)
- Désactiver temporairement Windows Defender
- Vérifier que ntdll.dll est accessible

**Détection par antivirus** :
- C'est normal ! C'est l'objectif du cours
- Ajouter une exception dans Windows Defender
- Tester les différentes techniques d'évasion

### Où Poser des Questions

1. Relire le cours théorique
2. Vérifier les commentaires dans le code
3. Consulter les exercices pratiques
4. Tester dans un environnement propre

---

## 📈 Progression Suggérée

```
Semaine 1 : Théorie + Setup
├─ Jour 1-2 : Lire COURS_SYSCALLS_EDR.md
├─ Jour 3-4 : Étudier SCHEMAS_VISUELS.md
├─ Jour 5   : Setup environnement (VM, outils)
└─ Jour 6-7 : Compiler et exécuter les démos

Semaine 2 : Pratique Débutant
├─ Jour 1-2 : Exercices 1-2
├─ Jour 3-4 : Exercice 3 (tests Defender)
└─ Jour 5-7 : Analyse du code source

Semaine 3 : Pratique Intermédiaire
├─ Jour 1-3 : Exercices 4-5
└─ Jour 4-7 : Exercice 6 (nouveaux syscalls)

Semaine 4 : Pratique Avancée
├─ Jour 1-3 : Exercices 7-8
└─ Jour 4-7 : Exercice 9 (unhooking)

Semaine 5-6 : Niveau Expert + Projet Final
└─ Combiner toutes les techniques
```

---

## ✅ Checklist Complète

### Lecture
- [ ] COURS_SYSCALLS_EDR.md lu entièrement
- [ ] SCHEMAS_VISUELS.md consulté
- [ ] GUIDE_SYSWHISPERS.md parcouru
- [ ] README.md lu
- [ ] EXERCICES_PRATIQUES.md étudié

### Compilation
- [ ] Environnement de développement configuré
- [ ] GCC installé et fonctionnel
- [ ] Tous les programmes compilés sans erreur
- [ ] Démonstrations exécutées avec succès

### Compréhension
- [ ] Architecture User/Kernel comprise
- [ ] Fonctionnement EDR compris
- [ ] Différence syscalls directs/indirects comprise
- [ ] Parsing PE compris
- [ ] Techniques d'évasion comprises

### Pratique
- [ ] Exercices débutant complétés
- [ ] Exercices intermédiaire complétés
- [ ] Exercices avancés complétés
- [ ] Exercices expert complétés
- [ ] Projet final réalisé

---

## 🎯 Objectif Final

**Créer votre propre loader furtif combinant :**
- ✅ Syscalls indirects
- ✅ Unhooking NTDLL
- ✅ Shellcode chiffré
- ✅ Évasion ETW
- ✅ Module stomping
- ✅ Sleep obfuscation

**Et comprendre comment les EDR modernes fonctionnent et comment les bypasser de manière éthique.**

---

Bon apprentissage ! 🚀🛡️

*Ce cours a été créé à des fins éducatives uniquement.*
*Utilisez de manière responsable et éthique.*
