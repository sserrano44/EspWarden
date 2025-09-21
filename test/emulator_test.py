#!/usr/bin/env python3
"""
ESP32 Remote Signer - Emulator Test Suite

This script tests the ESP32 Remote Signer running in QEMU emulator.
"""

import requests
import json
import time
import subprocess
import sys
import os
from typing import Dict, Optional
import hashlib
import hmac

# Disable SSL warnings for self-signed certificates
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ESP32EmulatorTest:
    """Test suite for ESP32 Remote Signer in emulator"""

    def __init__(self, base_url: str = "https://localhost:8443"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for self-signed cert
        self.auth_key = "0" * 64  # Default test auth key
        self.client_id = "emulator-test"

    def wait_for_device(self, timeout: int = 30) -> bool:
        """Wait for device to be responsive"""
        print(f"Waiting for device at {self.base_url}...")
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                response = self.session.get(f"{self.base_url}/health", timeout=1)
                if response.status_code == 200:
                    print("✅ Device is responsive")
                    return True
            except requests.exceptions.RequestException:
                pass
            time.sleep(1)

        print("❌ Device did not respond within timeout")
        return False

    def test_health_endpoint(self) -> bool:
        """Test /health endpoint"""
        print("\nTesting /health endpoint...")
        try:
            response = self.session.get(f"{self.base_url}/health")
            if response.status_code == 200:
                data = response.json()
                if "status" in data and "nonce" in data:
                    print(f"✅ Health check passed: {data}")
                    return True
            print(f"❌ Health check failed: {response.status_code}")
            return False
        except Exception as e:
            print(f"❌ Health check error: {e}")
            return False

    def test_info_endpoint(self) -> bool:
        """Test /info endpoint"""
        print("\nTesting /info endpoint...")
        try:
            response = self.session.get(f"{self.base_url}/info")
            if response.status_code == 200:
                data = response.json()
                print(f"Device Info: {json.dumps(data, indent=2)}")

                # Check device mode
                if "mode" in data:
                    mode = data["mode"]
                    print(f"Device Mode: {mode}")

                    # Verify mode matches expected GPIO state
                    expected_mode = os.environ.get("ESP32_PROVISIONING_MODE", "0")
                    if expected_mode == "1" and mode != "provisioning":
                        print("⚠️  Expected provisioning mode but got signing mode")
                    elif expected_mode == "0" and mode != "signing":
                        print("⚠️  Expected signing mode but got provisioning mode")
                    else:
                        print(f"✅ Device mode correct: {mode}")

                return True
            print(f"❌ Info check failed: {response.status_code}")
            return False
        except Exception as e:
            print(f"❌ Info check error: {e}")
            return False

    def generate_hmac(self, nonce: str, method: str, path: str, body: str = "") -> str:
        """Generate HMAC for authentication"""
        message = nonce + method + path + body
        auth_key_bytes = bytes.fromhex(self.auth_key)
        hmac_obj = hmac.new(auth_key_bytes, message.encode(), hashlib.sha256)
        return hmac_obj.hexdigest()

    def test_unlock_endpoint(self) -> Optional[str]:
        """Test /unlock endpoint"""
        print("\nTesting /unlock endpoint...")
        try:
            # Get nonce from health endpoint
            health_response = self.session.get(f"{self.base_url}/health")
            if health_response.status_code != 200:
                print("❌ Failed to get nonce from health endpoint")
                return None

            nonce = health_response.json().get("nonce", "")

            # Generate HMAC
            unlock_body = json.dumps({"clientId": self.client_id})
            hmac_value = self.generate_hmac(nonce, "POST", "/unlock", unlock_body)

            # Send unlock request
            unlock_data = {
                "clientId": self.client_id,
                "hmac": hmac_value
            }

            response = self.session.post(
                f"{self.base_url}/unlock",
                json=unlock_data,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 200:
                data = response.json()
                token = data.get("token")
                ttl = data.get("ttl")
                print(f"✅ Unlock successful - Token TTL: {ttl}s")
                return token
            else:
                print(f"❌ Unlock failed: {response.status_code}")
                print(f"Response: {response.text}")
                return None
        except Exception as e:
            print(f"❌ Unlock error: {e}")
            return None

    def test_provisioning_endpoints(self) -> bool:
        """Test provisioning mode endpoints"""
        print("\nTesting provisioning endpoints...")

        # These should only work in provisioning mode
        provisioning_endpoints = [
            ("/wifi", {"ssid": "TestNetwork", "psk": "testpassword"}),
            ("/auth", {"password": "test-provisioning-password"}),
            ("/key", {"mode": "generate"}),
            ("/policy", {
                "allowedChains": [1],
                "toWhitelist": ["0x742d35Cc3672C1BfeE3d4D5a0e6E9C4FfBe7E8A8"],
                "functionWhitelist": ["0xa9059cbb"],
                "maxValueWei": "0x16345785d8a0000",
                "maxGasLimit": 200000,
                "maxFeePerGasWei": "0x2540be400",
                "allowEmptyDataToWhitelist": True
            })
        ]

        mode = self.get_device_mode()

        for endpoint, data in provisioning_endpoints:
            try:
                response = self.session.post(
                    f"{self.base_url}{endpoint}",
                    json=data,
                    headers={"Content-Type": "application/json"}
                )

                if mode == "provisioning":
                    if response.status_code in [200, 501]:  # 501 for not implemented
                        print(f"✅ {endpoint}: Accessible in provisioning mode")
                    else:
                        print(f"❌ {endpoint}: Unexpected status {response.status_code}")
                else:  # signing mode
                    if response.status_code == 403:
                        print(f"✅ {endpoint}: Correctly blocked in signing mode")
                    else:
                        print(f"❌ {endpoint}: Should be blocked but got {response.status_code}")
            except Exception as e:
                print(f"❌ {endpoint}: Error - {e}")

        return True

    def get_device_mode(self) -> str:
        """Get current device mode"""
        try:
            response = self.session.get(f"{self.base_url}/info")
            if response.status_code == 200:
                return response.json().get("mode", "unknown")
        except:
            pass
        return "unknown"

    def run_all_tests(self) -> bool:
        """Run all tests"""
        print("=" * 50)
        print("ESP32 Remote Signer - Emulator Test Suite")
        print("=" * 50)

        if not self.wait_for_device():
            return False

        results = []
        results.append(self.test_health_endpoint())
        results.append(self.test_info_endpoint())

        # Test unlock (authentication)
        token = self.test_unlock_endpoint()
        results.append(token is not None)

        # Test provisioning endpoints
        results.append(self.test_provisioning_endpoints())

        print("\n" + "=" * 50)
        print("Test Results Summary:")
        passed = sum(results)
        total = len(results)
        print(f"Passed: {passed}/{total}")
        print("=" * 50)

        return all(results)


def main():
    """Main test runner"""
    # Check if emulator is running
    test = ESP32EmulatorTest()

    # Run tests
    success = test.run_all_tests()

    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()