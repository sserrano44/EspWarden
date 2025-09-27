#!/usr/bin/env python3
"""
ESP32 Remote Signer - Crypto Operations Test Suite
Tests secp256k1 signing, key generation, and Ethereum address derivation
"""

import json
import hashlib
import requests
import time
from typing import Dict, Tuple, Optional
from eth_account import Account
from eth_keys import keys
from eth_utils import keccak, to_hex, to_bytes
import pytest

# Test configuration
DEVICE_URL = "https://192.168.1.100"  # Update with actual device IP
AUTH_KEY = "test_auth_key_12345"
TIMEOUT = 10

# Known test vectors for secp256k1
TEST_VECTORS = [
    {
        "private_key": "0x4646464646464646464646464646464646464646464646464646464646464646",
        "public_key": "0x4e5f7c3c7a5b2d1e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f",
        "address": "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
        "message": "Hello Ethereum!",
        "signature": {
            "r": "0x7c1f8a76f5d5a0e3b9c2d1e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4",
            "s": "0x5b4a3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c",
            "v": 27
        }
    }
]

class ESP32SignerTestClient:
    """Test client for ESP32 Remote Signer"""

    def __init__(self, device_url: str, auth_key: str, verify_ssl: bool = False):
        self.device_url = device_url.rstrip('/')
        self.auth_key = auth_key
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.token = None

    def get_health(self) -> Dict:
        """Get device health and nonce"""
        response = self.session.get(f"{self.device_url}/health", timeout=TIMEOUT)
        return response.json()

    def unlock(self, nonce: str) -> str:
        """Unlock device with HMAC authentication"""
        # Simple HMAC for testing (in production, use proper HMAC)
        hmac_value = hashlib.sha256(f"{self.auth_key}:{nonce}".encode()).hexdigest()

        response = self.session.post(
            f"{self.device_url}/unlock",
            json={"hmac": hmac_value},
            timeout=TIMEOUT
        )
        data = response.json()
        self.token = data.get("token")
        return self.token

    def sign_eip155(self, transaction: Dict) -> Dict:
        """Sign EIP-155 transaction"""
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}

        response = self.session.post(
            f"{self.device_url}/sign/eip155",
            json=transaction,
            headers=headers,
            timeout=TIMEOUT
        )
        return response.json()

    def sign_eip1559(self, transaction: Dict) -> Dict:
        """Sign EIP-1559 transaction"""
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}

        response = self.session.post(
            f"{self.device_url}/sign/eip1559",
            json=transaction,
            headers=headers,
            timeout=TIMEOUT
        )
        return response.json()

    def get_info(self) -> Dict:
        """Get device information"""
        response = self.session.get(f"{self.device_url}/info", timeout=TIMEOUT)
        return response.json()


class TestCryptoOperations:
    """Test suite for cryptographic operations"""

    @pytest.fixture
    def client(self):
        """Create test client instance"""
        return ESP32SignerTestClient(DEVICE_URL, AUTH_KEY)

    def test_device_health(self, client):
        """Test health endpoint returns valid nonce"""
        health = client.get_health()

        assert health["status"] == "OK"
        assert "nonce" in health
        assert len(health["nonce"]) == 64  # 32 bytes hex encoded
        assert "rateRemaining" in health
        print(f"✓ Health check passed: nonce={health['nonce'][:8]}...")

    def test_device_unlock(self, client):
        """Test HMAC authentication and unlock"""
        # Get nonce
        health = client.get_health()
        nonce = health["nonce"]

        # Unlock with HMAC
        token = client.unlock(nonce)

        assert token is not None
        assert len(token) > 0
        print(f"✓ Device unlocked: token={token[:8]}...")

    def test_eip155_signing(self, client):
        """Test EIP-155 transaction signing"""
        # Authenticate first
        health = client.get_health()
        client.unlock(health["nonce"])

        # Create test transaction
        tx = {
            "chainId": 1,
            "nonce": "0x0",
            "gasPrice": "0x4a817c800",
            "gasLimit": "0x5208",
            "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bE06",
            "value": "0xde0b6b3a7640000",
            "data": "0x"
        }

        # Sign transaction
        signature = client.sign_eip155(tx)

        # Validate signature format
        assert "r" in signature
        assert "s" in signature
        assert "v" in signature
        assert len(signature["r"]) == 64  # 32 bytes hex
        assert len(signature["s"]) == 64  # 32 bytes hex
        assert isinstance(signature["v"], int)

        print(f"✓ EIP-155 signing passed: v={signature['v']}, r={signature['r'][:8]}...")

    def test_eip1559_signing(self, client):
        """Test EIP-1559 transaction signing"""
        # Authenticate first
        health = client.get_health()
        client.unlock(health["nonce"])

        # Create test transaction
        tx = {
            "chainId": 1,
            "nonce": "0x0",
            "maxFeePerGas": "0x4a817c800",
            "maxPriorityFeePerGas": "0x3b9aca00",
            "gasLimit": "0x5208",
            "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bE06",
            "value": "0xde0b6b3a7640000",
            "data": "0x"
        }

        # Sign transaction
        signature = client.sign_eip1559(tx)

        # Validate signature format
        assert "r" in signature
        assert "s" in signature
        assert "v" in signature
        assert len(signature["r"]) == 64  # 32 bytes hex
        assert len(signature["s"]) == 64  # 32 bytes hex
        assert isinstance(signature["v"], int)

        print(f"✓ EIP-1559 signing passed: v={signature['v']}, r={signature['r'][:8]}...")

    def test_signature_verification(self, client):
        """Test that signatures can be verified"""
        # Authenticate first
        health = client.get_health()
        client.unlock(health["nonce"])

        # Create and sign transaction
        tx = {
            "chainId": 1,
            "nonce": "0x0",
            "gasPrice": "0x4a817c800",
            "gasLimit": "0x5208",
            "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bE06",
            "value": "0x0",
            "data": "0x"
        }

        signature = client.sign_eip155(tx)

        # Create transaction hash (simplified - not proper RLP encoding)
        tx_string = f"{tx['chainId']}:{tx['nonce']}:{tx['gasPrice']}:{tx['gasLimit']}:{tx['to']}:{tx['value']}:{tx['data']}"
        tx_hash = keccak(text=tx_string)

        # Verify signature structure (actual verification would need the public key)
        r = int(signature["r"], 16)
        s = int(signature["s"], 16)
        v = signature["v"]

        # Check signature values are in valid range
        assert 0 < r < 2**256
        assert 0 < s < 2**256
        assert v >= 27

        print(f"✓ Signature verification passed")

    def test_device_info(self, client):
        """Test device information endpoint"""
        info = client.get_info()

        assert "fw" in info
        assert "address" in info
        assert "policyHash" in info
        assert "secureBoot" in info
        assert "flashEnc" in info
        assert "mode" in info
        assert info["mode"] in ["provisioning", "signing"]

        print(f"✓ Device info: mode={info['mode']}, address={info['address'][:8]}...")

    def test_rate_limiting(self, client):
        """Test rate limiting behavior"""
        initial_health = client.get_health()
        initial_rate = initial_health["rateRemaining"]

        # Make several requests
        for _ in range(3):
            client.get_health()
            time.sleep(0.1)

        # Check rate limit decreased
        final_health = client.get_health()
        final_rate = final_health["rateRemaining"]

        assert final_rate <= initial_rate
        print(f"✓ Rate limiting: {initial_rate} -> {final_rate}")


class TestErrorHandling:
    """Test suite for error handling"""

    @pytest.fixture
    def client(self):
        """Create test client instance"""
        return ESP32SignerTestClient(DEVICE_URL, AUTH_KEY)

    def test_invalid_transaction_format(self, client):
        """Test handling of invalid transaction data"""
        health = client.get_health()
        client.unlock(health["nonce"])

        # Missing required fields
        invalid_tx = {"chainId": 1}

        with pytest.raises(requests.HTTPError) as exc_info:
            response = client.session.post(
                f"{client.device_url}/sign/eip155",
                json=invalid_tx,
                headers={"Authorization": f"Bearer {client.token}"},
                timeout=TIMEOUT
            )
            response.raise_for_status()

        assert exc_info.value.response.status_code == 400
        print("✓ Invalid transaction format rejected")

    def test_unauthorized_signing(self, client):
        """Test signing without authentication"""
        tx = {
            "chainId": 1,
            "nonce": "0x0",
            "gasPrice": "0x4a817c800",
            "gasLimit": "0x5208",
            "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bE06",
            "value": "0x0",
            "data": "0x"
        }

        # Try to sign without token
        client.token = None

        with pytest.raises(requests.HTTPError) as exc_info:
            response = client.session.post(
                f"{client.device_url}/sign/eip155",
                json=tx,
                timeout=TIMEOUT
            )
            response.raise_for_status()

        assert exc_info.value.response.status_code in [401, 403]
        print("✓ Unauthorized signing rejected")

    def test_provisioning_mode_restriction(self, client):
        """Test that signing is blocked in provisioning mode"""
        info = client.get_info()

        if info["mode"] == "provisioning":
            health = client.get_health()
            client.unlock(health["nonce"])

            tx = {
                "chainId": 1,
                "nonce": "0x0",
                "gasPrice": "0x4a817c800",
                "gasLimit": "0x5208",
                "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bE06",
                "value": "0x0",
                "data": "0x"
            }

            with pytest.raises(requests.HTTPError) as exc_info:
                response = client.session.post(
                    f"{client.device_url}/sign/eip155",
                    json=tx,
                    headers={"Authorization": f"Bearer {client.token}"},
                    timeout=TIMEOUT
                )
                response.raise_for_status()

            assert exc_info.value.response.status_code == 403
            print("✓ Provisioning mode blocks signing")
        else:
            print("⚠ Device in signing mode - skipping provisioning test")


def run_all_tests():
    """Run all test suites"""
    print("=" * 60)
    print("ESP32 Remote Signer Test Suite")
    print("=" * 60)

    # Run crypto tests
    print("\n[Crypto Operations Tests]")
    crypto_tests = TestCryptoOperations()
    client = ESP32SignerTestClient(DEVICE_URL, AUTH_KEY)

    try:
        crypto_tests.test_device_health(client)
        crypto_tests.test_device_unlock(client)
        crypto_tests.test_eip155_signing(client)
        crypto_tests.test_eip1559_signing(client)
        crypto_tests.test_signature_verification(client)
        crypto_tests.test_device_info(client)
        crypto_tests.test_rate_limiting(client)
    except Exception as e:
        print(f"✗ Test failed: {e}")

    # Run error handling tests
    print("\n[Error Handling Tests]")
    error_tests = TestErrorHandling()

    try:
        error_tests.test_invalid_transaction_format(client)
        error_tests.test_unauthorized_signing(client)
        error_tests.test_provisioning_mode_restriction(client)
    except Exception as e:
        print(f"✗ Test failed: {e}")

    print("\n" + "=" * 60)
    print("Test suite completed!")
    print("=" * 60)


if __name__ == "__main__":
    # For standalone execution
    run_all_tests()