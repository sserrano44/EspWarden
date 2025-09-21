# ESP32 Remote Signer Makefile

# Default targets
.PHONY: build flash monitor clean menuconfig dev-build prod-build base-build

# Default build - uses base configuration (NO secure boot)
build: base-build

# Base build - secure boot DISABLED by default
base-build:
	@echo "Building with base configuration (secure boot DISABLED)..."
	cp sdkconfig.defaults.base sdkconfig.defaults
	idf.py build

# Development build - secure boot DISABLED, debug features enabled
dev-build:
	@echo "Building development version (secure boot DISABLED)..."
	@echo "Development builds prioritize debugging over security"
	cp sdkconfig.defaults.base sdkconfig.defaults
	cat sdkconfig.defaults.dev >> sdkconfig.defaults
	idf.py build

# Production build - secure boot ENABLED
prod-build:
	@echo "Building production version (secure boot ENABLED)..."
	@echo "WARNING: Requires secure boot signing key!"
	@if [ ! -f "secure_boot_signing_key.pem" ]; then \
		echo "ERROR: secure_boot_signing_key.pem not found!"; \
		echo "Run 'make generate-keys' first"; \
		exit 1; \
	fi
	cp sdkconfig.defaults.base sdkconfig.defaults
	cat sdkconfig.defaults.prod >> sdkconfig.defaults
	idf.py build

# Standard ESP-IDF targets
flash:
	idf.py flash

monitor:
	idf.py monitor

clean:
	idf.py clean

menuconfig:
	idf.py menuconfig

# Generate signing keys for secure boot (run once)
generate-keys:
	@echo "Generating secure boot signing key..."
	espsecure.py generate_signing_key --version 2 secure_boot_signing_key.pem

# Flash with secure boot (production)
flash-secure:
	idf.py bootloader
	espsecure.py sign_data --version 2 --keyfile secure_boot_signing_key.pem build/bootloader/bootloader.bin build/bootloader/bootloader-signed.bin
	esptool.py --chip esp32 --port /dev/ttyUSB0 write_flash 0x1000 build/bootloader/bootloader-signed.bin

# All-in-one development setup
dev-setup: dev-build flash monitor

# All-in-one production setup
prod-setup: generate-keys prod-build flash-secure

# Emulator build and run
emulator-build:
	@echo "Building for emulator (secure boot DISABLED)..."
	cp sdkconfig.defaults.base sdkconfig.defaults
	cat sdkconfig.emulator >> sdkconfig.defaults
	idf.py build

emulator-run:
	@echo "Starting emulator using ESP-IDF QEMU..."
	@echo "Note: Ensure ESP-IDF environment is sourced (. ~/esp/esp-idf/export.sh)"
	@echo "For interactive terminal: idf.py qemu monitor"
	@echo "For background mode: idf.py qemu"
	idf.py qemu monitor

# Run emulator in background (non-interactive)
emulator-run-bg:
	@echo "Starting emulator in background mode..."
	@echo "Note: Ensure ESP-IDF environment is sourced (. ~/esp/esp-idf/export.sh)"
	idf.py qemu &
	@sleep 2
	@echo "QEMU is running in background on localhost:5555"
	@echo "Connect with: nc localhost 5555"
	@echo "Or use: idf.py monitor -p socket://localhost:5555"

emulator-run-provisioning:
	@echo "Starting emulator in provisioning mode..."
	@echo "Note: GPIO simulation in QEMU requires custom configuration"
	./scripts/run_emulator.sh --provisioning

emulator-setup: emulator-build emulator-run

# Install QEMU ESP32 (macOS)
install-qemu-macos:
	@echo "Installing QEMU ESP32 for macOS..."
	@echo "Installing Homebrew dependencies..."
	brew install libgcrypt glib pixman sdl2 libslirp
	@echo "Installing QEMU via ESP-IDF tools..."
	idf_tools.py install qemu-xtensa qemu-riscv32
	@echo ""
	@echo "QEMU installed! To use it:"
	@echo "1. Source ESP-IDF: . ~/esp/esp-idf/export.sh"
	@echo "2. Run emulator: make emulator-run"

help:
	@echo "ESP32 Remote Signer - Build Targets:"
	@echo ""
	@echo "Basic targets:"
	@echo "  build       - Default build (secure boot DISABLED)"
	@echo "  flash       - Flash the firmware"
	@echo "  monitor     - Start serial monitor"
	@echo "  clean       - Clean build files"
	@echo "  menuconfig  - Open configuration menu"
	@echo ""
	@echo "Build configurations:"
	@echo "  base-build  - Base build (secure boot DISABLED)"
	@echo "  dev-build   - Development build (secure boot DISABLED + debug)"
	@echo "  prod-build  - Production build (secure boot ENABLED)"
	@echo ""
	@echo "Security:"
	@echo "  generate-keys - Generate secure boot keys (required for prod-build)"
	@echo "  flash-secure - Flash with secure boot (production only)"
	@echo ""
	@echo "Emulator:"
	@echo "  emulator-build - Build for emulator (secure boot DISABLED)"
	@echo "  emulator-run - Run in emulator (signing mode)"
	@echo "  emulator-run-provisioning - Run in emulator (provisioning mode)"
	@echo "  emulator-setup - Build and run in emulator"
	@echo "  install-qemu-macos - Install QEMU ESP32 on macOS"
	@echo ""
	@echo "Complete setups:"
	@echo "  dev-setup   - Complete development setup (no secure boot)"
	@echo "  prod-setup  - Complete production setup (with secure boot)"