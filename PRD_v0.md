# Product Requirements Document (PRD)

## 1. Product: ESP32 Remote Signer (Open‑Source Hot Signer)
**Status:** Draft v1.0  
**Owner:** @sebastian  
**Goal Release Window:** T+6 weeks from PRD sign‑off  

---

## 2. Problem & Opportunity
Running market‑making bots with private keys in `.env` files is risky. We need a low‑cost device that keeps the private key off the host, enforces on‑device policy (whitelists, caps), and provides a simple authenticated signing API. This is not a tamper‑proof HSM; it is a **remote signer** with strong at‑rest protections and policy gates suitable for hot balances with limited blast radius.

---

## 3. Objectives & Non‑Goals
### 3.1 Objectives (v1.0)
- Keep the Ethereum private key **off the host**, stored encrypted on device.
- Enforce **policy** on the device before signing (address/ABI selector whitelist, value and gas caps, allowed chains).
- Provide a **local HTTPS API** with challenge‑response authentication.
- Support **EIP‑155/EIP‑1559** transaction signing (secp256k1 + keccak).
- Two‑pin **provisioning mode** hardware gate; otherwise read‑only (signing) mode.

### 3.2 Non‑Goals (v1.0)
- Tamper resistance comparable to commercial HSMs.
- Multi‑party computation (MPC) or threshold signing.
- Cross‑chain support beyond Ethereum‑compatible chains.
- USB HID wallet UX, Seed phrase display, or on‑device screen/confirmations.

---

## 4. Users & Use Cases
- **Bot Operator/DevOps**: Deploys device, provisions Wi‑Fi, sets key and policy, points trading bot at the signer.
- **Security Engineer**: Reviews policy, audits logs, rotates credentials.

**Primary Use Case**: Market‑making bot requests signatures for whitelisted contracts, under enforced limits. Device signs only if policy allows.

---

## 5. Scope (v1.0)
### 5.1 Hardware
- Target board: **ESP32 NodeMCU‑32S** (or equivalent with Secure Boot + Flash Encryption).  
- GPIO: 2 dedicated pins for **Provisioning Jumper** detection (shorted at boot ⇒ provisioning mode).  
- Optional: Status LED.

### 5.2 Firmware/OS
- SDK: **ESP‑IDF** (preferred) or Arduino core on ESP32 with mbedTLS and NVS.  
- Features: Secure Boot (v2), Flash Encryption (NVS & app partitions), disable JTAG in production, hardware RNG usage.

### 5.3 Crypto
- Curve: secp256k1.  
- Hash: Keccak‑256 for message hashing (Ethereum).  
- Schemes: legacy EIP‑155 and EIP‑1559 transaction signing.  
- Library: trezor‑crypto or micro‑ecc (static linked).

### 5.4 Key & Policy Storage
- **Key material**: device‑generated or imported seed/private key stored in **encrypted NVS**. Never logged or returned.
- **Policy**: JSON blob in encrypted NVS.
- **Auth secret**: 256‑bit HMAC key derived from provisioning password (scrypt/PBKDF2); only the derived key stored.

### 5.5 Device Modes
- **Provisioning Mode** (pins shorted at boot): allow writes to key, Wi‑Fi SSID/PSK, auth setup, and policy.  
- **Signing Mode** (pins open): deny all mutation APIs; only auth, info, and sign endpoints allowed.

### 5.6 Network/API
- Transport: **HTTPS** (self‑signed device cert) or HTTP on LAN (configurable; default HTTPS).  
- Auth: challenge‑response **HMAC(nonce || method || path || body)** with rolling nonce; session token (TTL≤60s).  
- Rate limit: default **10 sign requests/min** (configurable).  
- Replay protection with device‑issued nonces and per‑session window.

---

## 6. Functional Requirements

### 6.1 Provisioning Flow
**HSM‑REQ‑001**: If GPIO_A and GPIO_B are shorted at boot, enter **Provisioning Mode**; otherwise **Signing Mode**.  
**HSM‑REQ‑002**: In Provisioning Mode, device exposes endpoints to set Wi‑Fi, key, auth password, and policy.  
**HSM‑REQ‑003**: On first provisioning, device can **generate** a new key (TRNG) or **import** a provided seed/private key.  
**HSM‑REQ‑004**: After successful provisioning, reboot is required to switch to Signing Mode.

### 6.2 Authentication
**HSM‑REQ‑010**: Device maintains a 256‑bit **AUTH_KEY** (derived via scrypt from a provisioning password with device‑unique salt).  
**HSM‑REQ‑011**: `POST /unlock` accepts `{clientId, hmac(auth_key, nonce||clientId)}` and returns a **short‑lived token** (≤60s).  
**HSM‑REQ‑012**: All mutating endpoints require **Provisioning Mode** plus valid HMAC; `sign` requires valid token.  
**HSM‑REQ‑013**: Nonces are single‑use, expire in ≤60s; replayed requests are rejected.

### 6.3 Policy Enforcement
**HSM‑REQ‑020**: Policy schema supports:  
- `allowedChains: number[]`  
- `toWhitelist: string[]` (EVM addresses)  
- `functionWhitelist: string[]` (4‑byte selectors, hex)  
- `maxValueWei: string`  
- `maxGasLimit: number`  
- `maxFeePerGasWei: string` (for EIP‑1559)  
- `allowEmptyDataToWhitelist: boolean`  
**HSM‑REQ‑021**: Before signing, device **must** validate: chainId, `to` in whitelist, selector (if data), caps for `value`, `gasLimit`, and `maxFeePerGas`.
**HSM‑REQ‑022**: If `data` is empty and `to` is whitelisted, allow only if `allowEmptyDataToWhitelist=true`.
**HSM‑REQ‑023**: Provide a policy hash in `/info` for external audit.

### 6.4 Signing
**HSM‑REQ‑030**: Support `POST /sign/eip1559` with body:
```json
{
  "token":"...",
  "tx":{
    "chainId": 1,
    "nonce": "0x...",
    "maxFeePerGas": "0x...",
    "maxPriorityFeePerGas": "0x...",
    "gasLimit": "0x...",
    "to": "0x...",
    "value": "0x...",
    "data": "0x..."
  }
}
```
Response: `{ "r":"0x..","s":"0x..","v":27|28 }` and optionally the fully serialized `raw`.

**HSM‑REQ‑031**: Implement EIP‑155 legacy path via `POST /sign/eip155` with gasPrice/gas.
**HSM‑REQ‑032**: Signing must use keccak‑256 over the correct EIP‑1559/155 payload; deterministic RFC6979‑style nonce or library default.
**HSM‑REQ‑033**: Latency target: **p50 ≤ 50 ms**, **p95 ≤ 150 ms** for sign operation on LAN.

### 6.5 Info & Health
**HSM‑REQ‑040**: `GET /info` returns: firmware version, device public key & Ethereum address, policy hash, Secure‑Boot/Flash‑Enc status, uptime.
**HSM‑REQ‑041**: `GET /health` returns OK + rate‑limit remaining and nonce for next unlock.

### 6.6 Rate Limiting & Abuse Controls
**HSM‑REQ‑050**: Global token bucket: default 10 sign/min; configurable in provisioning.
**HSM‑REQ‑051**: Per‑client optional caps (requests/min) keyed by `clientId`.
**HSM‑REQ‑052**: Backoff on repeated auth failures; temporary ban after N failures (default 10/min).

### 6.7 Logging & Telemetry
**HSM‑REQ‑060**: No sensitive data (keys, secrets) ever logged.  
**HSM‑REQ‑061**: Log: timestamp, clientId, endpoint, decision (ALLOW/DENY), policy reason code, p50/95 lat.  
**HSM‑REQ‑062**: Logs accessible via serial console and optional `/logs` (Signing Mode read‑only).

### 6.8 OTA & Firmware Integrity
**HSM‑REQ‑070**: (Optional v1.0) Local OTA update in Provisioning Mode only; firmware must be Secure‑Boot signed.  
**HSM‑REQ‑071**: Reject unsigned or downgraded firmware.

### 6.9 Wipe/Reset
**HSM‑REQ‑080**: `POST /wipe` only available in Provisioning Mode **and** requires correct HMAC. Wipes key, policy, Wi‑Fi, and auth.

---

## 7. Non‑Functional Requirements
- **Security at Rest**: Flash Encryption enabled; NVS encrypted; JTAG disabled; no plaintext secrets in RAM longer than necessary.  
- **Availability**: device should recover automatically on power cycle; boot ≤ 3s; reconnect Wi‑Fi ≤ 10s.  
- **Compatibility**: Node.js bots via simple HTTP(S) client; no SDK required.  
- **Documentation**: README with wiring diagram (jumper), API, policy examples, and sample Node.js client.

---

## 8. API (v1.0) — Endpoints

### 8.1 Public (both modes)
- `GET /health` → `{status, nonce, rateRemaining}`
- `GET /info` → `{fw, address, policyHash, secureBoot:true/false, flashEnc:true/false}`
- `POST /unlock` → `{token, ttl}` (HMAC over nonce)

### 8.2 Provisioning Mode Only
- `POST /wifi` → `{ssid, psk}`
- `POST /auth` → `{password}` (derives and stores AUTH_KEY)
- `POST /key` → `{mode:"generate"|"import", seed|privkey}`
- `POST /policy` → policy JSON (see §6.3)
- `POST /wipe` → factory reset

### 8.3 Signing Mode Only
- `POST /sign/eip155` → legacy tx
- `POST /sign/eip1559` → EIP‑1559 tx

**Errors**: JSON `{code, message, reason}`; include reason codes like `POLICY_TO_NOT_WHITELISTED`, `POLICY_SELECTOR_DENIED`, `CAP_VALUE`, `AUTH_FAILED`, `RATE_LIMIT`.

---

## 9. Policy JSON Schema (draft)
```json
{
  "allowedChains": {"type":"array","items":{"type":"integer"}},
  "toWhitelist": {"type":"array","items":{"type":"string","pattern":"^0x[0-9a-fA-F]{40}$"}},
  "functionWhitelist": {"type":"array","items":{"type":"string","pattern":"^0x[0-9a-fA-F]{8}$"}},
  "maxValueWei": {"type":"string","pattern":"^0x?[0-9a-fA-F]+$"},
  "maxGasLimit": {"type":"integer","minimum":21000},
  "maxFeePerGasWei": {"type":"string","pattern":"^0x?[0-9a-fA-F]+$"},
  "allowEmptyDataToWhitelist": {"type":"boolean"}
}
```

---

## 10. Acceptance Criteria
1. Device boots into **Signing Mode** when pins are open; **Provisioning Mode** when shorted.  
2. In Signing Mode, any attempt to call `/policy`, `/key`, `/wifi`, `/auth` returns `403` with `MODE_READ_ONLY`.  
3. With a valid policy allowing a `transfer(address,uint256)` to a whitelisted `to`, device returns a valid ECDSA `(r,s,v)` and serialized tx; external node can broadcast successfully.  
4. A request violating policy (e.g., non‑whitelisted selector or `value` above cap) returns `403` with correct reason code; **no signature produced**.  
5. Replay of a previous `sign` request with stale token is rejected.  
6. Rate limit enforced (default 10/min) with `429` on excess.  
7. `/info` shows stable address, policy hash, and `secureBoot/flashEnc` flags set to true in production build.  
8. Wipe fully resets device; subsequent `/info` shows no key and policy.

---

## 11. Milestones
- **M1 (Week 1‑2):** Hardware bring‑up, Wi‑Fi, HTTPS server scaffold, nonce/HMAC auth.  
- **M2 (Week 3‑4):** Key storage, signing (EIP‑1559), policy engine, rate limiting.  
- **M3 (Week 5):** Secure Boot + Flash Encryption production build; error codes; logging.  
- **M4 (Week 6):** Docs, sample Node.js client, tests, alpha tag.

---

## 12. Testing Strategy
- **Unit tests**: policy evaluation, selector parsing, hex validation, nonce cache.  
- **Crypto tests**: known‑answer vectors for secp256k1 & keccak; cross‑check signatures with ethers.js.  
- **Integration**: end‑to‑end Node client → device → broadcast on a testnet.  
- **Security smoke**: replay attempts, rate‑limit bypass attempts, invalid lengths, malformed JSON, large payloads (DoS).  
- **Persistence**: power loss mid‑write; verify atomic NVS updates and recovery.

---

## 13. Risks & Mitigations
- **Not a true HSM**: Communicate constraints; enforce low balances & strict policy; document threat model.  
- **Wi‑Fi exposure**: Default HTTPS + strong auth; allow LAN‑only mode; optional IP allowlist.  
- **Library bugs**: Choose mature crypto libs; pin versions; run known‑answer tests.  
- **Provisioning mistakes**: Hardware jumper gate + explicit mode banner in `/info`.

---

## 14. Open Questions
1. Do we require **mTLS** in v1.0 or defer to v1.1?  
2. Should we support **raw (r,s,v)** only or always return **serialized `raw` tx**?  
3. Minimum supported set of chains (1, 10, 8453?) and default gas caps?  
4. Add a **physical confirm button** for high‑risk selectors (e.g., `approve()`)?

---

## 15. Out of Scope (v1.0)
- UART/USB host APIs; WebUSB; BLE.  
- Display/UX for seed phrases.  
- Secure element co‑processor; MPC.

---

## 16. Deliverables
- Firmware repo (ESP‑IDF), build scripts, signed release binaries.  
- Hardware reference (pinout + jumper wiring).  
- Policy schema & examples.  
- Sample Node.js client with retry/rate‑limit handling.  
- Deployment guide (provisioning → signing mode) and threat model README.

