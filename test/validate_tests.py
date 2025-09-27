#!/usr/bin/env python3
"""
ESP32 Remote Signer - Test Suite Validator

This script validates that the test suite is properly configured and can run.
Run this before committing changes or setting up CI/CD.
"""

import os
import sys
import subprocess
import importlib
import json
from pathlib import Path

class TestValidator:
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.test_dir = Path(__file__).parent
        self.errors = []
        self.warnings = []

    def check_python_dependencies(self):
        """Check that all Python dependencies are available"""
        print("🐍 Checking Python dependencies...")

        required_packages = [
            'pytest', 'requests', 'eth_utils', 'eth_keys',
            'eth_account', 'web3', 'pyserial'
        ]

        missing = []
        for package in required_packages:
            try:
                # Special case for pyserial which imports as 'serial'
                module_name = 'serial' if package == 'pyserial' else package.replace('-', '_')
                importlib.import_module(module_name)
                print(f"  ✓ {package}")
            except ImportError:
                missing.append(package)
                print(f"  ✗ {package} (missing)")

        if missing:
            self.errors.append(f"Missing Python packages: {', '.join(missing)}")
            print(f"  💡 Install with: pip install {' '.join(missing)}")

        return len(missing) == 0

    def check_esp_idf(self):
        """Check ESP-IDF environment"""
        print("\n🔧 Checking ESP-IDF environment...")

        idf_path = os.environ.get('IDF_PATH')
        if not idf_path:
            self.warnings.append("ESP-IDF not sourced (some tests will be skipped)")
            print("  ⚠ ESP-IDF not sourced")
            print("  💡 Run: source ~/esp/esp-idf/export.sh")
            return False

        print(f"  ✓ IDF_PATH: {idf_path}")

        # Check idf.py command
        try:
            result = subprocess.run(['idf.py', '--version'],
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                version = result.stdout.strip()
                print(f"  ✓ idf.py version: {version}")
            else:
                self.warnings.append("idf.py not working properly")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.warnings.append("idf.py not found in PATH")

        return True

    def check_test_files(self):
        """Check that all test files exist and are valid"""
        print("\n📄 Checking test files...")

        required_files = [
            'test_crypto.py',
            'emulator_test.py',
            'run_tests.sh',
            'requirements.txt',
            'unit/test_crypto_unit.c'
        ]

        missing = []
        for file_path in required_files:
            full_path = self.test_dir / file_path
            if full_path.exists():
                print(f"  ✓ {file_path}")
            else:
                missing.append(file_path)
                print(f"  ✗ {file_path} (missing)")

        if missing:
            self.errors.append(f"Missing test files: {', '.join(missing)}")

        return len(missing) == 0

    def check_build_system(self):
        """Check that build system works"""
        print("\n🔨 Checking build system...")

        # Check Makefile
        makefile = self.project_root / 'Makefile'
        if makefile.exists():
            print("  ✓ Makefile found")
        else:
            self.errors.append("Makefile not found")
            return False

        # Check build targets
        try:
            result = subprocess.run(['make', 'help'],
                                  cwd=self.project_root,
                                  capture_output=True, text=True, timeout=10)
            if 'emulator-build' in result.stdout:
                print("  ✓ Emulator build target available")
            else:
                self.warnings.append("Emulator build target not found")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.warnings.append("Could not run make command")

        return True

    def check_syntax(self):
        """Check Python syntax of test files"""
        print("\n🔍 Checking Python syntax...")

        python_files = [
            'test_crypto.py',
            'emulator_test.py',
            'validate_tests.py'
        ]

        syntax_errors = []
        for file_path in python_files:
            full_path = self.test_dir / file_path
            if not full_path.exists():
                continue

            try:
                with open(full_path, 'r') as f:
                    compile(f.read(), file_path, 'exec')
                print(f"  ✓ {file_path}")
            except SyntaxError as e:
                syntax_errors.append(f"{file_path}: {e}")
                print(f"  ✗ {file_path} (syntax error)")

        if syntax_errors:
            self.errors.extend(syntax_errors)

        return len(syntax_errors) == 0

    def check_test_runner_executable(self):
        """Check that test runner script is executable"""
        print("\n🏃 Checking test runner...")

        runner_script = self.test_dir / 'run_tests.sh'
        if runner_script.exists():
            if os.access(runner_script, os.X_OK):
                print("  ✓ run_tests.sh is executable")
            else:
                self.warnings.append("run_tests.sh is not executable")
                print("  ⚠ run_tests.sh not executable")
                print("  💡 Run: chmod +x test/run_tests.sh")
        else:
            self.errors.append("run_tests.sh not found")

        return True

    def check_trezor_crypto_integration(self):
        """Check trezor-crypto component integration"""
        print("\n🔐 Checking trezor-crypto integration...")

        trezor_crypto_dir = self.project_root / 'components' / 'trezor-crypto'
        if trezor_crypto_dir.exists():
            print("  ✓ trezor-crypto component found")

            # Check CMakeLists.txt
            cmake_file = trezor_crypto_dir / 'CMakeLists.txt'
            if cmake_file.exists():
                print("  ✓ CMakeLists.txt found")
            else:
                self.errors.append("trezor-crypto CMakeLists.txt missing")

            # Check key files
            key_files = ['secp256k1.c', 'ecdsa.c', 'sha3.c']
            for key_file in key_files:
                if (trezor_crypto_dir / key_file).exists():
                    print(f"  ✓ {key_file}")
                else:
                    self.warnings.append(f"trezor-crypto {key_file} not found")
        else:
            self.errors.append("trezor-crypto component not found")
            print("  ✗ trezor-crypto component missing")
            print("  💡 Run: git submodule update --init --recursive")

        return trezor_crypto_dir.exists()

    def run_basic_import_test(self):
        """Test that we can import our test modules"""
        print("\n📦 Testing module imports...")

        test_modules = ['test_crypto', 'emulator_test']
        import_errors = []

        # Add test directory to path
        sys.path.insert(0, str(self.test_dir))

        for module in test_modules:
            try:
                importlib.import_module(module)
                print(f"  ✓ {module}")
            except ImportError as e:
                import_errors.append(f"{module}: {e}")
                print(f"  ✗ {module} (import error)")

        if import_errors:
            self.warnings.extend(import_errors)

        return len(import_errors) == 0

    def generate_report(self):
        """Generate validation report"""
        print("\n" + "="*60)
        print("VALIDATION REPORT")
        print("="*60)

        if not self.errors and not self.warnings:
            print("🎉 ALL CHECKS PASSED!")
            print("\nYour test suite is ready to use:")
            print("  ./test/run_tests.sh all")
            return True

        if self.errors:
            print(f"\n❌ ERRORS ({len(self.errors)}):")
            for i, error in enumerate(self.errors, 1):
                print(f"  {i}. {error}")

        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for i, warning in enumerate(self.warnings, 1):
                print(f"  {i}. {warning}")

        print("\n📋 NEXT STEPS:")
        if self.errors:
            print("  1. Fix all errors listed above")
            print("  2. Re-run this validator")
        if self.warnings:
            print("  3. Address warnings for optimal testing")

        print("\n📖 For help, see:")
        print("  - docs/TESTING.md")
        print("  - docs/TESTING_QUICK_START.md")

        return len(self.errors) == 0

    def run_validation(self):
        """Run all validation checks"""
        print("ESP32 Remote Signer - Test Suite Validator")
        print("="*60)

        checks = [
            self.check_python_dependencies,
            self.check_esp_idf,
            self.check_test_files,
            self.check_build_system,
            self.check_syntax,
            self.check_test_runner_executable,
            self.check_trezor_crypto_integration,
            self.run_basic_import_test
        ]

        results = []
        for check in checks:
            try:
                results.append(check())
            except Exception as e:
                self.errors.append(f"Validation error: {e}")
                results.append(False)

        return self.generate_report()


def main():
    """Main entry point"""
    validator = TestValidator()
    success = validator.run_validation()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()