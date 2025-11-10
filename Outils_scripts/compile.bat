@echo off
REM ============================================================================
REM SCRIPT DE COMPILATION - SYSCALLS EDR
REM ============================================================================
REM
REM Ce script compile tous les programmes de démonstration
REM
REM USAGE :
REM   compile.bat           - Compile tous les programmes
REM   compile.bat direct    - Compile uniquement syscalls directs
REM   compile.bat indirect  - Compile uniquement syscalls indirects
REM   compile.bat demo      - Compile uniquement la démonstration
REM   compile.bat clean     - Nettoie les fichiers compilés
REM
REM ============================================================================

echo.
echo ╔══════════════════════════════════════════════════════╗
echo ║  SYSCALLS DIRECTS ET INDIRECTS - COMPILATION        ║
echo ╚══════════════════════════════════════════════════════╝
echo.

REM Vérifier que GCC est installé
where gcc >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [!] ERREUR : GCC n'est pas installé ou pas dans le PATH
    echo.
    echo Pour installer GCC sur Windows :
    echo   1. Installer MSYS2 : https://www.msys2.org/
    echo   2. Ouvrir MSYS2 terminal
    echo   3. Exécuter : pacman -S mingw-w64-x86_64-gcc
    echo   4. Ajouter au PATH : C:\msys64\mingw64\bin
    echo.
    pause
    exit /b 1
)

REM Options de compilation
set CFLAGS=-Wall -Wextra -O2 -std=c11
set LDFLAGS=-lntdll -s

REM Traiter les arguments
if "%1"=="clean" goto :clean
if "%1"=="direct" goto :compile_direct
if "%1"=="indirect" goto :compile_indirect
if "%1"=="demo" goto :compile_demo
if "%1"=="" goto :compile_all

echo [!] Argument invalide : %1
echo Usage : compile.bat [all^|direct^|indirect^|demo^|clean]
goto :end

:compile_all
echo [*] Compilation de tous les programmes...
echo.
call :compile_direct
call :compile_indirect
call :compile_demo
echo.
echo ╔══════════════════════════════════════════════════════╗
echo ║  COMPILATION TERMINÉE AVEC SUCCÈS !                  ║
echo ╚══════════════════════════════════════════════════════╝
echo.
echo Fichiers générés :
echo   • syscalls_direct.exe   - Démonstration syscalls directs
echo   • syscalls_indirect.exe - Démonstration syscalls indirects
echo   • demo_injection.exe    - Injection de shellcode complète
echo.
goto :end

:compile_direct
echo [*] Compilation de syscalls_direct.exe...
gcc %CFLAGS% -DCOMPILE_DEMO_DIRECT syscalls_direct.c -o syscalls_direct.exe %LDFLAGS%
if %ERRORLEVEL% EQU 0 (
    echo [+] syscalls_direct.exe créé avec succès
) else (
    echo [-] Erreur lors de la compilation de syscalls_direct.exe
)
echo.
goto :eof

:compile_indirect
echo [*] Compilation de syscalls_indirect.exe...
gcc %CFLAGS% -DCOMPILE_DEMO_INDIRECT syscalls_indirect.c -o syscalls_indirect.exe %LDFLAGS%
if %ERRORLEVEL% EQU 0 (
    echo [+] syscalls_indirect.exe créé avec succès
) else (
    echo [-] Erreur lors de la compilation de syscalls_indirect.exe
)
echo.
goto :eof

:compile_demo
echo [*] Compilation de demo_injection.exe...
gcc %CFLAGS% demo_injection.c syscalls_indirect.c -o demo_injection.exe %LDFLAGS%
if %ERRORLEVEL% EQU 0 (
    echo [+] demo_injection.exe créé avec succès
) else (
    echo [-] Erreur lors de la compilation de demo_injection.exe
)
echo.
goto :eof

:clean
echo [*] Nettoyage des fichiers compilés...
if exist syscalls_direct.exe del /F /Q syscalls_direct.exe
if exist syscalls_indirect.exe del /F /Q syscalls_indirect.exe
if exist demo_injection.exe del /F /Q demo_injection.exe
if exist *.o del /F /Q *.o
echo [+] Nettoyage terminé
echo.
goto :end

:end
pause
