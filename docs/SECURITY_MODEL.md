# Security Model

This document describes the security model, threat analysis, and limitations of the ESP32 Remote Signer.

## Overview

The ESP32 Remote Signer is designed as a **policy-enforced remote signer** for Ethereum transactions. It is **NOT** a Hardware Security Module (HSM) and should not be used for high-value or critical applications.

## Security Features

### Hardware Security

#### ✅ Secure Boot v2
- Prevents execution of unsigned firmware
- RSA-3072 signature verification
- Boot-time integrity checking
- Protects against firmware tampering

#### ✅ Flash Encryption
- AES-256 encryption of flash contents
- Hardware-encrypted key storage
- Protects private keys at rest
- Prevents flash memory dumping

#### ✅ Hardware Random Number Generator
- True random number generation for:
  - Private key generation
  - Nonce generation
  - Session token creation
- ESP32 TRNG meets cryptographic standards

### Software Security

#### ✅ Encrypted NVS Storage
- All sensitive data encrypted in non-volatile storage
- Separate encryption keys for different data types
- Atomic write operations to prevent corruption

#### ✅ Challenge-Response Authentication
- HMAC-SHA256 based authentication
- Rolling nonces prevent replay attacks
- Time-limited session tokens (≤60 seconds)
- Client identification and rate limiting

#### ✅ Policy Enforcement
- Mandatory transaction validation before signing
- Address whitelisting
- Function selector filtering
- Value and gas limit caps
- Chain ID validation

#### ✅ Rate Limiting
- Token bucket algorithm
- Per-client and global limits
- Exponential backoff on failures
- Abuse prevention mechanisms

## Threat Model

### Protected Against

#### ✅ Host System Compromise
**Threat:** Malware on the host system attempts to steal private keys or sign unauthorized transactions.

**Protection:**
- Private keys never leave the ESP32 device
- All transactions must pass policy validation
- Authentication required for each signing session

#### ✅ Network Eavesdropping
**Threat:** Attacker intercepts network traffic to steal credentials or replay transactions.

**Protection:**
- HTTPS encryption for all communications
- Challenge-response authentication prevents credential theft
- Nonce-based replay protection

#### ✅ Unauthorized Transaction Signing
**Threat:** Attacker attempts to sign transactions outside policy parameters.

**Protection:**
- Mandatory policy validation on-device
- Whitelist-based access control
- Value and gas limit enforcement

#### ✅ Brute Force Attacks
**Threat:** Attacker attempts to guess authentication credentials.

**Protection:**
- 256-bit authentication keys
- Rate limiting with exponential backoff
- Account lockout after repeated failures

### NOT Protected Against

#### ❌ Physical Access
**Threat:** Attacker has physical access to the device.

**Vulnerability:**
- Could perform hardware-level attacks
- Side-channel analysis possible
- Debug interfaces may be exploitable
- Flash encryption keys extractable with advanced techniques

**Mitigation:**
- Use tamper-evident enclosures
- Deploy in secure physical locations
- Monitor device for unauthorized access

#### ❌ Supply Chain Attacks
**Threat:** Malicious firmware or hardware modifications during manufacturing/shipping.

**Vulnerability:**
- Compromised development boards
- Modified firmware during shipping
- Malicious components

**Mitigation:**
- Source hardware from trusted suppliers
- Verify firmware integrity
- Build firmware from source
- Use secure boot with your own keys

#### ❌ Advanced Persistent Threats (APT)
**Threat:** Nation-state or advanced attackers with significant resources.

**Vulnerability:**
- Zero-day exploits in ESP-IDF
- Hardware-level backdoors
- Sophisticated side-channel attacks
- Social engineering of operators

**Mitigation:**
- This device is not suitable for high-security applications
- Use dedicated HSMs for critical operations
- Implement defense-in-depth strategies

#### ❌ Quantum Computer Attacks
**Threat:** Quantum computers breaking secp256k1 cryptography.

**Vulnerability:**
- Current cryptographic algorithms vulnerable to quantum attacks
- Private keys could be recovered from public keys
- Digital signatures could be forged

**Mitigation:**
- Monitor quantum-resistant cryptography developments
- Plan migration strategy for post-quantum algorithms
- Consider this a long-term risk (10+ years)

## Risk Assessment

### High Risk Scenarios (DO NOT USE)

❌ **Large Treasury Management**
- Risk: High-value targets for attackers
- Impact: Significant financial loss
- Recommendation: Use dedicated HSMs

❌ **Critical Infrastructure**
- Risk: Systemic failure impact
- Impact: Service disruption, safety issues
- Recommendation: Use certified secure hardware

❌ **Regulatory Compliance**
- Risk: Non-compliance with security standards
- Impact: Legal/regulatory penalties
- Recommendation: Use compliant security solutions

### Medium Risk Scenarios (USE WITH CAUTION)

⚠️ **Automated Trading (Limited Funds)**
- Risk: Policy bypass or exploitation
- Mitigation: Strict policies, limited exposure
- Monitoring: Active surveillance required

⚠️ **DeFi Protocol Interaction**
- Risk: Smart contract vulnerabilities
- Mitigation: Contract whitelisting, limited permissions
- Monitoring: Transaction monitoring

### Low Risk Scenarios (ACCEPTABLE USE)

✅ **Development and Testing**
- Use for developing signing workflows
- Test transaction policies
- Prototype automated systems

✅ **Educational Projects**
- Learn about hardware security
- Understand signing infrastructure
- Demonstrate security concepts

✅ **Small-Scale Automation**
- Limited-value operations
- Well-defined whitelists
- Monitored environments

## Security Best Practices

### Deployment

1. **Physical Security**
   - Deploy in locked, monitored locations
   - Use tamper-evident enclosures
   - Limit physical access to authorized personnel

2. **Network Security**
   - Use dedicated network segments
   - Implement firewall rules
   - Monitor network traffic

3. **Operational Security**
   - Regular firmware updates
   - Security monitoring and alerting
   - Incident response procedures

### Configuration

1. **Strong Authentication**
   - Use high-entropy authentication keys
   - Rotate keys periodically
   - Secure key distribution

2. **Restrictive Policies**
   - Minimal necessary permissions
   - Conservative value limits
   - Regular policy reviews

3. **Rate Limiting**
   - Conservative rate limits
   - Per-client restrictions
   - Monitoring for abuse

### Monitoring

1. **Transaction Monitoring**
   - Log all signing requests
   - Monitor for policy violations
   - Alert on suspicious patterns

2. **Device Health**
   - Regular health checks
   - Firmware integrity monitoring
   - Performance metrics

3. **Security Events**
   - Failed authentication attempts
   - Rate limit violations
   - Unusual transaction patterns

## Compliance Considerations

### Standards NOT Met

- **FIPS 140-2:** No certification or evaluation
- **Common Criteria:** No security certification
- **SOC 2:** No audit or compliance program
- **PCI DSS:** Not designed for payment applications

### Regulatory Implications

- **Financial Services:** Likely not suitable for regulated environments
- **Critical Infrastructure:** Does not meet security requirements
- **Government Use:** Insufficient security assurance

## Incident Response

### Security Incident Types

1. **Device Compromise**
   - Immediately disable device
   - Rotate all credentials
   - Investigate attack vector

2. **Policy Violations**
   - Review transaction logs
   - Update policies if needed
   - Monitor for repeated violations

3. **Authentication Failures**
   - Check for brute force attacks
   - Verify credential integrity
   - Consider key rotation

### Recovery Procedures

1. **Device Reset**
   - Use provisioning mode wipe function
   - Reconfigure with new credentials
   - Update all policies

2. **Key Rotation**
   - Generate new authentication keys
   - Update client configurations
   - Verify secure key distribution

## Conclusion

The ESP32 Remote Signer provides meaningful security improvements over storing private keys on host systems, but it is not a substitute for professional HSMs in high-security environments.

**Use this device only for:**
- Development and testing
- Low-value automated operations
- Educational purposes
- Proof-of-concept implementations

**For production critical applications, invest in:**
- Certified Hardware Security Modules
- Professional key management solutions
- Comprehensive security audits
- Regulatory compliance programs

Remember: **Security is a journey, not a destination.** Continuously evaluate your threat model and security requirements as your application evolves.