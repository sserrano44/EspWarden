# ESP32 Remote Signer Makefile

# Development build (flash encryption in development mode)
.PHONY: build flash monitor clean menuconfig dev-build prod-build

build:
	idf.py build

flash:
	idf.py flash

monitor:
	idf.py monitor

clean:
	idf.py clean

menuconfig:
	idf.py menuconfig

# Development build with development flash encryption
dev-build:
	@echo "Building development version with development flash encryption..."
	cp sdkconfig.defaults.dev sdkconfig.defaults
	idf.py build

# Production build with release flash encryption
prod-build:
	@echo "Building production version with release flash encryption..."
	cp sdkconfig.defaults.prod sdkconfig.defaults
	idf.py build

# Generate signing keys for secure boot (run once)
generate-keys:
	@echo "Generating secure boot signing key..."
	mkdir -p keys
	espsecure.py generate_signing_key --version 2 keys/secure_boot_signing_key.pem

# Flash with secure boot (production)
flash-secure:
	idf.py bootloader
	espsecure.py sign_data --version 2 --keyfile keys/secure_boot_signing_key.pem build/bootloader/bootloader.bin build/bootloader/bootloader-signed.bin
	esptool.py --chip esp32 --port /dev/ttyUSB0 write_flash 0x1000 build/bootloader/bootloader-signed.bin

# All-in-one development setup
dev-setup: dev-build flash monitor

# All-in-one production setup
prod-setup: generate-keys prod-build flash-secure

help:
	@echo "Available targets:"
	@echo "  build       - Build the project"
	@echo "  flash       - Flash the firmware"
	@echo "  monitor     - Start serial monitor"
	@echo "  clean       - Clean build files"
	@echo "  menuconfig  - Open configuration menu"
	@echo "  dev-build   - Build development version"
	@echo "  prod-build  - Build production version"
	@echo "  generate-keys - Generate secure boot keys"
	@echo "  flash-secure - Flash with secure boot"
	@echo "  dev-setup   - Complete development setup"
	@echo "  prod-setup  - Complete production setup"