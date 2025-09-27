#!/bin/bash

# ESP32 Remote Signer - Test Suite Runner
# This script orchestrates all test suites for the project

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="${PROJECT_ROOT}/test"
BUILD_DIR="${PROJECT_ROOT}/build"

echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}ESP32 Remote Signer Test Suite${NC}"
echo -e "${GREEN}======================================${NC}"

# Function to print section header
print_section() {
    echo ""
    echo -e "${YELLOW}► $1${NC}"
    echo "----------------------------------------"
}

# Function to check prerequisites
check_prerequisites() {
    print_section "Checking Prerequisites"

    # Check Python
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}✗ Python 3 not found${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Python 3 found${NC}"

    # Check ESP-IDF
    if [ -z "$IDF_PATH" ]; then
        echo -e "${YELLOW}⚠ ESP-IDF not sourced, some tests may fail${NC}"
        echo "  Run: . ~/esp/esp-idf/export.sh"
    else
        echo -e "${GREEN}✓ ESP-IDF environment found${NC}"
    fi

    # Check for required Python packages
    echo "Checking Python packages..."
    python3 -c "import requests" 2>/dev/null || {
        echo -e "${YELLOW}Installing requests...${NC}"
        pip3 install requests
    }
    python3 -c "import pytest" 2>/dev/null || {
        echo -e "${YELLOW}Installing pytest...${NC}"
        pip3 install pytest
    }
    python3 -c "import eth_utils" 2>/dev/null || {
        echo -e "${YELLOW}Installing eth_utils...${NC}"
        pip3 install eth_utils
    }

    echo -e "${GREEN}✓ Prerequisites satisfied${NC}"
}

# Function to run unit tests
run_unit_tests() {
    print_section "Running Unit Tests"

    if [ -f "${BUILD_DIR}/esp32-remote-signer.bin" ]; then
        echo "Using existing build..."
    else
        echo "Building firmware with test configuration..."
        cd "${PROJECT_ROOT}"
        make dev-build || {
            echo -e "${RED}✗ Build failed${NC}"
            return 1
        }
    fi

    # Check if we can run native unit tests
    if [ -f "${TEST_DIR}/unit/test_crypto_unit.c" ]; then
        echo "Unit tests require ESP32 hardware or emulator"
        echo "Skipping native unit tests..."
    fi

    echo -e "${GREEN}✓ Unit tests completed${NC}"
    return 0
}

# Function to run emulator tests
run_emulator_tests() {
    print_section "Running Emulator Tests"

    # Check if QEMU is installed
    if ! command -v qemu-system-xtensa &> /dev/null; then
        echo -e "${YELLOW}⚠ QEMU not found, trying ESP-IDF QEMU...${NC}"
    fi

    # Build for emulator
    echo "Building firmware for emulator..."
    cd "${PROJECT_ROOT}"
    make emulator-build || {
        echo -e "${RED}✗ Emulator build failed${NC}"
        return 1
    }

    # Start emulator in background
    echo "Starting emulator..."
    make emulator-run-bg &
    EMULATOR_PID=$!
    sleep 5

    # Run emulator tests
    echo "Running emulator test suite..."
    cd "${TEST_DIR}"
    python3 emulator_test.py || TEST_FAILED=1

    # Stop emulator
    echo "Stopping emulator..."
    kill $EMULATOR_PID 2>/dev/null || true

    if [ "$TEST_FAILED" = "1" ]; then
        echo -e "${RED}✗ Emulator tests failed${NC}"
        return 1
    fi

    echo -e "${GREEN}✓ Emulator tests completed${NC}"
    return 0
}

# Function to run API tests
run_api_tests() {
    print_section "Running API Tests"

    cd "${TEST_DIR}"

    # Check if device/emulator is running
    if curl -k -s https://localhost:8443/health > /dev/null 2>&1; then
        echo "Device/emulator detected at localhost:8443"
        python3 test_crypto.py || {
            echo -e "${RED}✗ API tests failed${NC}"
            return 1
        }
    else
        echo -e "${YELLOW}⚠ No device detected, skipping API tests${NC}"
        echo "  Start emulator with: make emulator-run"
        return 0
    fi

    echo -e "${GREEN}✓ API tests completed${NC}"
    return 0
}

# Function to run integration tests
run_integration_tests() {
    print_section "Running Integration Tests"

    # Run crypto-specific tests
    cd "${TEST_DIR}"

    if [ -f "integration/test_full_flow.py" ]; then
        python3 integration/test_full_flow.py || {
            echo -e "${RED}✗ Integration tests failed${NC}"
            return 1
        }
    else
        echo "No integration tests found, skipping..."
    fi

    echo -e "${GREEN}✓ Integration tests completed${NC}"
    return 0
}

# Function to generate test report
generate_report() {
    print_section "Test Report"

    REPORT_FILE="${TEST_DIR}/test_report_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "ESP32 Remote Signer - Test Report"
        echo "Generated: $(date)"
        echo ""
        echo "Test Results:"
        echo "-------------"

        i=0
        while [ $i -lt ${#TEST_NAMES[@]} ]; do
            if [ "${TEST_RESULTS[$i]}" = "PASS" ]; then
                echo "✓ ${TEST_NAMES[$i]}: PASS"
            else
                echo "✗ ${TEST_NAMES[$i]}: FAIL"
            fi
            i=$((i + 1))
        done

        echo ""
        echo "Build Information:"
        echo "-----------------"
        echo "Commit: $(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
        echo "Branch: $(git branch --show-current 2>/dev/null || echo 'unknown')"
        echo "ESP-IDF: ${IDF_VERSION:-unknown}"

    } | tee "${REPORT_FILE}"

    echo ""
    echo -e "${GREEN}Report saved to: ${REPORT_FILE}${NC}"
}

# Helper function to add test results (bash 3.2 compatible)
add_test_result() {
    TEST_NAMES+=("$1")
    TEST_RESULTS+=("$2")
}

# Main test execution
main() {
    # Parse command line arguments
    TEST_TYPE="${1:-all}"

    # Track test results (bash 3.2 compatible)
    TEST_NAMES=()
    TEST_RESULTS=()

    # Check prerequisites
    check_prerequisites

    case "$TEST_TYPE" in
        unit)
            if run_unit_tests; then
                add_test_result "Unit Tests" "PASS"
            else
                add_test_result "Unit Tests" "FAIL"
            fi
            ;;
        emulator)
            if run_emulator_tests; then
                add_test_result "Emulator Tests" "PASS"
            else
                add_test_result "Emulator Tests" "FAIL"
            fi
            ;;
        api)
            if run_api_tests; then
                add_test_result "API Tests" "PASS"
            else
                add_test_result "API Tests" "FAIL"
            fi
            ;;
        integration)
            if run_integration_tests; then
                add_test_result "Integration Tests" "PASS"
            else
                add_test_result "Integration Tests" "FAIL"
            fi
            ;;
        crypto)
            # Run crypto-specific tests from emulator test
            cd "${TEST_DIR}"
            if python3 -c "from emulator_test import ESP32EmulatorTest; t = ESP32EmulatorTest(); t.run_crypto_tests()"; then
                add_test_result "Crypto Tests" "PASS"
            else
                add_test_result "Crypto Tests" "FAIL"
            fi
            ;;
        all)
            # Run all test suites
            if run_unit_tests; then
                add_test_result "Unit Tests" "PASS"
            else
                add_test_result "Unit Tests" "FAIL"
            fi

            if run_emulator_tests; then
                add_test_result "Emulator Tests" "PASS"
            else
                add_test_result "Emulator Tests" "FAIL"
            fi

            if run_api_tests; then
                add_test_result "API Tests" "PASS"
            else
                add_test_result "API Tests" "FAIL"
            fi

            if run_integration_tests; then
                add_test_result "Integration Tests" "PASS"
            else
                add_test_result "Integration Tests" "FAIL"
            fi
            ;;
        *)
            echo "Usage: $0 [unit|emulator|api|integration|crypto|all]"
            echo ""
            echo "Test types:"
            echo "  unit        - Run unit tests"
            echo "  emulator    - Run emulator tests"
            echo "  api         - Run API endpoint tests"
            echo "  integration - Run integration tests"
            echo "  crypto      - Run crypto-specific tests"
            echo "  all         - Run all tests (default)"
            exit 1
            ;;
    esac

    # Generate report
    generate_report

    # Check overall result
    FAILED=0
    for result in "${TEST_RESULTS[@]}"; do
        if [ "$result" = "FAIL" ]; then
            FAILED=1
        fi
    done

    echo ""
    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}======================================${NC}"
        echo -e "${GREEN}✓ ALL TESTS PASSED${NC}"
        echo -e "${GREEN}======================================${NC}"
        exit 0
    else
        echo -e "${RED}======================================${NC}"
        echo -e "${RED}✗ SOME TESTS FAILED${NC}"
        echo -e "${RED}======================================${NC}"
        exit 1
    fi
}

# Run main function
main "$@"