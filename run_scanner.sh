#!/bin/bash
# Paranoid - Advanced iOS Spyware Detection Tool
# Runner script for easy execution on macOS/Linux

clear

# ANSI colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Display header
echo -e "${BLUE}"
echo "  ___  _   ___ _   _  _ ___ ___ ___  "
echo " / _ \/_\ | _ \ /_\ | \| / _ \_ _|   \ "
echo "| (_) / _ \|   / _ \| .` \(_) | || |) |"
echo " \___/_/ \_\_|_/_/ \_\_|\_\___/___|___/ "
echo -e "${NC}"
echo "Advanced iOS Spyware Detection Tool"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}ERROR: Python 3 not found. Please install Python 3.7 or higher.${NC}"
    exit 1
fi

# Main menu function
show_menu() {
    echo ""
    echo -e "${CYAN}=== MAIN MENU ===${NC}"
    echo "1) Run Full Scan"
    echo "2) Run Pegasus-specific Scan"
    echo "3) Show IOC Database"
    echo "4) Show Prerequisites"
    echo "5) Show Risk Matrix"
    echo "6) Version Information"
    echo "7) Exit"
    echo ""
}

# Full scan function
run_full_scan() {
    echo ""
    echo -e "${CYAN}=== FULL SCAN ===${NC}"
    echo ""
    echo "The scanner needs the path to your iTunes backup directory."
    echo "This is typically located at:"
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "~/Library/Application Support/MobileSync/Backup/[BACKUP-ID]"
        echo ""
        echo "To list your backups, run:"
        echo "ls ~/Library/Application\ Support/MobileSync/Backup/"
    else
        echo "~/.local/share/MobileSync/Backup/[BACKUP-ID]"
        echo "or another custom location"
    fi
    
    echo ""
    
    read -p "Enter your backup path: " backup_path
    
    if [ -z "$backup_path" ]; then
        echo -e "${RED}ERROR: Backup path cannot be empty.${NC}"
        return
    fi
    
    echo ""
    echo "Optional: Enter path to diagnostic files if available"
    read -p "Diagnostic files path (press Enter to skip): " diag_path
    echo ""
    
    if [ -z "$diag_path" ]; then
        echo "Running scan on backup only..."
        python3 spyware_detector.py --backup "$backup_path"
    else
        echo "Running scan on backup and diagnostic files..."
        python3 spyware_detector.py --backup "$backup_path" --diagnostic "$diag_path"
    fi
    
    read -p "Press Enter to continue..."
}

# Pegasus scan function
run_pegasus_scan() {
    echo ""
    echo -e "${CYAN}=== PEGASUS SCAN ===${NC}"
    echo ""
    echo "This scan focuses specifically on detecting Pegasus spyware."
    echo "The scanner needs the path to your iTunes backup directory."
    echo ""
    
    read -p "Enter your backup path: " backup_path
    
    if [ -z "$backup_path" ]; then
        echo -e "${RED}ERROR: Backup path cannot be empty.${NC}"
        return
    fi
    
    echo ""
    echo "Optional: Enter path to diagnostic files if available"
    read -p "Diagnostic files path (press Enter to skip): " diag_path
    echo ""
    
    if [ -z "$diag_path" ]; then
        echo "Running Pegasus scan on backup only..."
        python3 AdvancedSpywareDetector.py --backup "$backup_path"
    else
        echo "Running Pegasus scan on backup and diagnostic files..."
        python3 AdvancedSpywareDetector.py --backup "$backup_path" --diagnostic "$diag_path"
    fi
    
    read -p "Press Enter to continue..."
}

# Main program loop
while true; do
    show_menu
    read -p "Enter your choice (1-7): " choice
    
    case $choice in
        1) run_full_scan ;;
        2) run_pegasus_scan ;;
        3)
            echo ""
            echo -e "${CYAN}=== IOC DATABASE ===${NC}"
            echo ""
            python3 spyware_detector.py --ioc-database
            read -p "Press Enter to continue..."
            ;;
        4)
            echo ""
            echo -e "${CYAN}=== PREREQUISITES ===${NC}"
            echo ""
            python3 spyware_detector.py --prerequisites
            read -p "Press Enter to continue..."
            ;;
        5)
            echo ""
            echo -e "${CYAN}=== RISK ASSESSMENT MATRIX ===${NC}"
            echo ""
            python3 spyware_detector.py --risk-map
            read -p "Press Enter to continue..."
            ;;
        6)
            echo ""
            echo -e "${CYAN}=== VERSION INFORMATION ===${NC}"
            echo ""
            python3 spyware_detector.py --version
            read -p "Press Enter to continue..."
            ;;
        7) 
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice. Please try again.${NC}"
            ;;
    esac
    
    clear
done