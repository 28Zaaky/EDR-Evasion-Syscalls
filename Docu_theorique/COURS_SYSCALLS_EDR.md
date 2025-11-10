# Cours : Syscalls Directs et Indirects - Évasion EDR

## 📚 Partie 1 : Théorie

### 1.1 Introduction aux Syscalls

Les **syscalls** (appels système) sont l'interface entre les applications en mode utilisateur (User Mode) et le noyau Windows (Kernel Mode). Ils permettent d'effectuer des opérations privilégiées comme la gestion de la mémoire, des processus, des fichiers, etc.

#### Architecture Windows : User Mode vs Kernel Mode

```
┌─────────────────────────────────────────┐
│         Application (User Mode)         │
│                                         │
│  ┌───────────────────────────────────┐ │
│  │   API Win32 (kernel32.dll, etc)  │ │
│  └───────────────┬───────────────────┘ │
│                  │                      │
│  ┌───────────────▼───────────────────┐ │
│  │      NTDLL.dll (ntdll.dll)       │ │
│  │  - NtAllocateVirtualMemory       │ │
│  │  - NtCreateThreadEx              │ │
│  │  - NtWriteVirtualMemory          │ │
│  └───────────────┬───────────────────┘ │
└──────────────────┼──────────────────────┘
                   │ SYSCALL instruction
                   │ (Transition User→Kernel)
┌──────────────────▼──────────────────────┐
│         Windows Kernel (Ring 0)         │
│                                         │
│  - Gestion de la mémoire               │
│  - Gestion des processus               │
│  - Drivers et matériel                 │
└─────────────────────────────────────────┘
```

### 1.2 Comment fonctionnent les EDR ?

Les **EDR** (Endpoint Detection and Response) surveillent les comportements suspects sur les endpoints. Leur stratégie principale : **le hooking**.

#### Le Hooking NTDLL par les EDR

Les EDR modifient les fonctions dans `ntdll.dll` pour intercepter les appels système :

```
┌─────────────────────────────────────────┐
│  Version Normale de NtAllocateVM       │
├─────────────────────────────────────────┤
│  4C 8B D1          mov r10, rcx        │ ← Prolog original
│  B8 18 00 00 00    mov eax, 0x18       │ ← Numéro de syscall
│  0F 05             syscall              │ ← Exécution du syscall
│  C3                ret                   │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│  Version HOOKÉE par l'EDR              │
├─────────────────────────────────────────┤
│  E9 XX XX XX XX    jmp EDR_Hook        │ ← HOOK installé !
│  00 00 00 00                            │
│  0F 05             syscall              │
│  C3                ret                   │
└─────────────────────────────────────────┘
```

Quand l'EDR hook une fonction :
1. Il remplace les premiers bytes par un `JMP` vers son code
2. Il analyse les paramètres (PID cible, permissions, taille mémoire)
3. Il décide si l'opération est malveillante
4. Il peut bloquer ou logger l'opération

### 1.3 Syscalls Directs : Bypasser les Hooks

L'idée des **syscalls directs** : **appeler directement le kernel sans passer par ntdll.dll hookée**.

#### Avantages :
✅ Bypass total des hooks EDR dans ntdll.dll  
✅ Pas de détection par analyse des API calls  
✅ Comportement "légitime" du point de vue kernel  

#### Inconvénients :
❌ Numéros de syscall différents selon les versions Windows  
❌ Signature suspecte en mémoire (instructions `syscall`)  
❌ Détectable par analyse comportementale avancée  

### 1.4 Syscalls Indirects : Plus Furtif

Les **syscalls indirects** vont encore plus loin : ils utilisent une copie propre de ntdll.dll pour :
1. Extraire les numéros de syscall
2. Trouver l'adresse d'une instruction `syscall` dans ntdll non hookée
3. Préparer les registres et sauter vers cette instruction

#### Avantages supplémentaires :
✅ Pas d'instruction `syscall` dans notre code malveillant  
✅ Réutilisation du code légitime de Windows  
✅ Plus difficile à détecter statiquement  
✅ Résolution dynamique des syscalls  

#### Le Processus :

```
1. Charger une copie fraîche de ntdll.dll depuis le disque
   └─> Aucun hook EDR présent

2. Parser le PE de ntdll pour trouver NtAllocateVirtualMemory
   └─> Extraire le numéro de syscall (SSN)

3. Trouver une instruction "syscall; ret" dans ntdll
   └─> Adresse légitime pour exécuter le syscall

4. Préparer les registres (R10, RAX, etc.)

5. Sauter vers l'instruction syscall dans ntdll
   └─> L'EDR voit un appel depuis ntdll (légitime !)
```

### 1.5 Détection et Contre-mesures EDR

Les EDR modernes commencent à détecter ces techniques :

#### Détections possibles :
- **ETW (Event Tracing for Windows)** : Surveillance au niveau kernel
- **Callback Kernel** : Interception des opérations sensibles
- **Analyse comportementale** : Pattern d'allocations mémoire suspectes
- **Stack walking** : Vérification de la call stack
- **AMSI (Antimalware Scan Interface)** : Scan des buffers mémoire

#### Contre-contre-mesures :
- Sleep obfuscation (Ekko, Foliage)
- Module stomping
- Indirect syscalls avec randomisation
- Unhooking NTDLL
- Patching ETW

---

## 🔧 Partie 2 : Implémentation Technique

### Structure du code :

1. **syscalls_direct.c** : Implémentation des syscalls directs
2. **syscalls_indirect.c** : Implémentation des syscalls indirects (plus avancé)
3. **syscalls.h** : Header avec les structures et prototypes
4. **demo_injection.c** : Démonstration pratique d'injection de shellcode

Les fichiers sont créés dans le dossier suivant avec commentaires détaillés.
