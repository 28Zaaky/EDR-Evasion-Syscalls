# ⚠️ Problème de Compilation

## Erreur Rencontrée

```
error: unknown register name 'r8' in 'asm'
error: unknown register name 'r10' in 'asm'
```

## Cause

Vous utilisez **MinGW 32-bit** (`MinGW.org GCC-6.3.0-1`) qui ne supporte pas les registres x64 (r8-r15) nécessaires pour l'assembleur inline.

Ce projet nécessite **MinGW-w64** pour compiler du code x64.

## Solution: Installer MinGW-w64

### Méthode 1: Via MSYS2 (Recommandée)

1. **Télécharger MSYS2**
   - Site: https://www.msys2.org/
   - Installer dans `C:\msys64`

2. **Installer GCC x64**
   ```bash
   # Ouvrir MSYS2
   pacman -Syu
   pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-make
   ```

3. **Ajouter au PATH**
   - Ouvrir "Variables d'environnement"
   - Ajouter: `C:\msys64\mingw64\bin`
   - **Important**: Mettre AVANT le chemin de MinGW 32-bit

4. **Vérifier l'installation**
   ```powershell
   gcc --version
   # Doit afficher: x86_64-w64-mingw32
   ```

### Méthode 2: Téléchargement Direct

1. Télécharger MinGW-w64 depuis: https://sourceforge.net/projects/mingw-w64/
2. Choisir architecture: **x86_64**
3. Installer dans `C:\mingw64`
4. Ajouter au PATH: `C:\mingw64\bin`

## Compilation Après Installation

```powershell
# Méthode 1: Avec Make
cd Code_source
make

# Méthode 2: Manuelle
gcc -Wall -O2 -masm=intel -DCOMPILE_DEMO_INDIRECT syscalls_indirect.c -o syscalls_indirect.exe -lntdll -s
```

## Vérification du Compilateur

```powershell
# Vérifier que c'est bien MinGW-w64 x64
gcc --version | findstr "x86_64"

# Si aucun résultat, c'est encore MinGW 32-bit
```

## Alternative: Compilation Sans Assembleur Inline

Si vous ne pouvez pas installer MinGW-w64, vous pouvez créer un fichier `.asm` séparé et l'assembler avec NASM:

```powershell
# Installer NASM
# https://www.nasm.us/

# Assembler
nasm -f win64 syscalls.asm -o syscalls.obj

# Linker avec GCC
gcc syscalls_indirect.c syscalls.obj -o syscalls_indirect.exe -lntdll
```

Mais cette méthode est plus complexe et sort du cadre de ce cours.

---

**Note**: Une fois MinGW-w64 installé, tous les fichiers de ce projet compileront correctement.
