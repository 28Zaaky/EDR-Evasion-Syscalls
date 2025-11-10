# ============================================================================
# Script de Compilation - Syscalls Indirects
# ============================================================================
#
# Ce script compile syscalls_indirect.c avec les bonnes options
# et vérifie que MinGW-w64 (x64) est installé
#
# ============================================================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Compilation: Syscalls Indirects" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Vérifier que GCC est installé
Write-Host "[*] Vérification du compilateur..." -ForegroundColor Yellow

try {
    $gccVersion = & gcc --version 2>$null | Select-Object -First 1
    Write-Host "    Compilateur: $gccVersion" -ForegroundColor Gray
    
    # Vérifier si c'est MinGW-w64 (x64)
    if ($gccVersion -match "x86_64") {
        Write-Host "[+] MinGW-w64 (x64) détecté" -ForegroundColor Green
    }
    else {
        Write-Host "[!] ATTENTION: MinGW 32-bit détecté" -ForegroundColor Red
        Write-Host "" -ForegroundColor Red
        Write-Host "    Ce projet nécessite MinGW-w64 (64-bit) pour compiler" -ForegroundColor Red
        Write-Host "    car il utilise l'assembleur inline x64 (registres r8-r15)" -ForegroundColor Red
        Write-Host "" -ForegroundColor Red
        Write-Host "    Installation MinGW-w64:" -ForegroundColor Yellow
        Write-Host "    1. Télécharger depuis: https://www.msys2.org/" -ForegroundColor Yellow
        Write-Host "    2. Installer MSYS2" -ForegroundColor Yellow
        Write-Host "    3. Ouvrir MSYS2 et exécuter:" -ForegroundColor Yellow
        Write-Host "       pacman -S mingw-w64-x86_64-gcc" -ForegroundColor Yellow
        Write-Host "    4. Ajouter au PATH: C:\msys64\mingw64\bin" -ForegroundColor Yellow
        Write-Host "" -ForegroundColor Red
        Write-Host "    Consultez COMPILATION_GUIDE.md pour plus de détails" -ForegroundColor Yellow
        Write-Host "" -ForegroundColor Red
        
        $continue = Read-Host "Continuer quand même? (la compilation échouera) [o/N]"
        if ($continue -ne "o" -and $continue -ne "O") {
            Write-Host "[!] Compilation annulée" -ForegroundColor Red
            exit 1
        }
    }
}
catch {
    Write-Host "[-] GCC n'est pas installé ou n'est pas dans le PATH" -ForegroundColor Red
    Write-Host "    Installez MinGW-w64 depuis: https://www.msys2.org/" -ForegroundColor Yellow
    exit 1
}

Write-Host ""

# Paramètres de compilation
$sourceFile = "syscalls_indirect.c"
$outputFile = "syscalls_indirect.exe"
$cflags = "-Wall -O2 -masm=intel -DCOMPILE_DEMO_INDIRECT"
$ldflags = "-lntdll -s"

# Vérifier que le fichier source existe
if (-not (Test-Path $sourceFile)) {
    Write-Host "[-] Fichier source introuvable: $sourceFile" -ForegroundColor Red
    Write-Host "    Assurez-vous d'être dans le répertoire Code_source/" -ForegroundColor Yellow
    exit 1
}

# Compilation
Write-Host "[*] Compilation en cours..." -ForegroundColor Yellow
Write-Host "    gcc $cflags $sourceFile -o $outputFile $ldflags" -ForegroundColor Gray
Write-Host ""

try {
    $compileCommand = "gcc $cflags $sourceFile -o $outputFile $ldflags"
    Invoke-Expression $compileCommand
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host " [+] Compilation réussie!" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "    Fichier créé: $outputFile" -ForegroundColor Green
        
        # Obtenir la taille du fichier
        $fileSize = (Get-Item $outputFile).Length
        Write-Host "    Taille: $fileSize bytes" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Exécution:" -ForegroundColor Cyan
        Write-Host "    .\$outputFile" -ForegroundColor Yellow
        Write-Host ""
    }
    else {
        Write-Host "" -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Red
        Write-Host " [-] Compilation échouée!" -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Red
        Write-Host ""
        Write-Host "Si vous voyez 'unknown register name r8/r10/r11':" -ForegroundColor Yellow
        Write-Host "  -> Vous devez installer MinGW-w64 (x64)" -ForegroundColor Yellow
        Write-Host "  -> Consultez COMPILATION_GUIDE.md" -ForegroundColor Yellow
        Write-Host ""
        exit 1
    }
}
catch {
    Write-Host "[-] Erreur lors de la compilation: $_" -ForegroundColor Red
    exit 1
}
