@echo off
REM Paranoid - Advanced iOS Spyware Detection Tool for Windows
REM Runner script for easy execution

echo.
echo   ___  _   ___ _   _  _ ___ ___ ___  
echo  / _ \/_\ | _ \ /_\ | \| / _ \_ _|   \ 
echo | (_) / _ \|   / _ \| .` \(_) | || |) |
echo  \___/_/ \_\_|_/_/ \_\_|\_\___/___|___/ 
echo.
echo Advanced iOS Spyware Detection Tool
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python not found. Please install Python 3.7 or higher.
    echo Visit: https://www.python.org/downloads/windows/
    goto :EOF
)

REM Display main menu
:MENU
echo.
echo === MAIN MENU ===
echo [1] Run Full Scan
echo [2] Run Pegasus-specific Scan
echo [3] Show IOC Database
echo [4] Show Prerequisites
echo [5] Show Risk Matrix
echo [6] Version Information
echo [7] Exit
echo.

set /p choice=Enter your choice (1-7): 

if "%choice%"=="1" goto FULL_SCAN
if "%choice%"=="2" goto PEGASUS_SCAN
if "%choice%"=="3" goto IOC_DATABASE
if "%choice%"=="4" goto PREREQUISITES
if "%choice%"=="5" goto RISK_MATRIX
if "%choice%"=="6" goto VERSION_INFO
if "%choice%"=="7" goto :EOF

echo Invalid choice. Please try again.
goto MENU

:FULL_SCAN
echo.
echo === FULL SCAN ===
echo.
echo The scanner needs the path to your iTunes backup directory.
echo This is typically located at:
echo %%APPDATA%%\Apple Computer\MobileSync\Backup\[BACKUP-ID]
echo.
echo To list your backups, run:
echo dir "%%APPDATA%%\Apple Computer\MobileSync\Backup"
echo.

set /p backup_path=Enter your backup path: 

if "%backup_path%"=="" (
    echo ERROR: Backup path cannot be empty.
    goto MENU
)

echo.
echo Optional: Enter path to diagnostic files if available
set /p diag_path=Diagnostic files path (press Enter to skip): 
echo.

if "%diag_path%"=="" (
    echo Running scan on backup only...
    python spyware_detector.py --backup "%backup_path%"
) else (
    echo Running scan on backup and diagnostic files...
    python spyware_detector.py --backup "%backup_path%" --diagnostic "%diag_path%"
)

pause
goto MENU

:PEGASUS_SCAN
echo.
echo === PEGASUS SCAN ===
echo.
echo This scan focuses specifically on detecting Pegasus spyware.
echo The scanner needs the path to your iTunes backup directory.
echo.

set /p backup_path=Enter your backup path: 

if "%backup_path%"=="" (
    echo ERROR: Backup path cannot be empty.
    goto MENU
)

echo.
echo Optional: Enter path to diagnostic files if available
set /p diag_path=Diagnostic files path (press Enter to skip): 
echo.

if "%diag_path%"=="" (
    echo Running Pegasus scan on backup only...
    python AdvancedSpywareDetector.py --backup "%backup_path%"
) else (
    echo Running Pegasus scan on backup and diagnostic files...
    python AdvancedSpywareDetector.py --backup "%backup_path%" --diagnostic "%diag_path%"
)

pause
goto MENU

:IOC_DATABASE
echo.
echo === IOC DATABASE ===
echo.
python spyware_detector.py --ioc-database
pause
goto MENU

:PREREQUISITES
echo.
echo === PREREQUISITES ===
echo.
python spyware_detector.py --prerequisites
pause
goto MENU

:RISK_MATRIX
echo.
echo === RISK ASSESSMENT MATRIX ===
echo.
python spyware_detector.py --risk-map
pause
goto MENU

:VERSION_INFO
echo.
echo === VERSION INFORMATION ===
echo.
python spyware_detector.py --version
pause
goto MENU