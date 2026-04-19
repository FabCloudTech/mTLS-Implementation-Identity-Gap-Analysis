# mTLS Implementation & Identity Gap Analysis

**Client:** Grand Marina Hotel  
**System:** Hydroficient HYDROLOGIC Water Monitoring System  
**Analyst:** Fabella Terry  
**Date:** April 2026  
**Externship:** Hydroficient IoT Cybersecurity Externship

---

## Overview

Mutual TLS (mTLS) implementation on a Mosquitto broker to enforce certificate-based device identity for IoT sensors. Includes gap analysis identifying three attack scenarios where one-way TLS fails, live certificate validation testing, and identity-bound logging via CN extraction.

## The Problem with One-Way TLS

One-way TLS encrypts traffic but does not verify *who the client is*. Three attack scenarios succeed against one-way TLS alone:

| Scenario | Attack | One-Way TLS | mTLS |
|---|---|---|---|
| A | Rogue broker impersonation | ❌ Vulnerable | ✅ Client verifies server cert |
| B | Compromised sensor publishing false data | ❌ Vulnerable | ✅ Broker rejects unrecognized cert |
| C | Insider bypass — connecting with stolen credentials | ❌ Vulnerable | ✅ No cert = no connection |

## Implementation

### Certificate Generation

```bash
# CA Certificate
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=Hydroficient-CA"

# Server Certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=mqtt-broker"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365

# Client Certificate (per device)
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=sensor-main-building"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
```

### Mosquitto Configuration

```
listener 8883
cafile /etc/mosquitto/certs/ca.crt
certfile /etc/mosquitto/certs/server.crt
keyfile /etc/mosquitto/certs/server.key
require_certificate true
use_identity_as_username true
tls_version tlsv1.2
```

### Identity-Bound Logging

`use_identity_as_username true` extracts the certificate Common Name (CN) and uses it as the username in broker logs — creating a cryptographically verified audit trail.

```
1712345678: New connection from 192.168.1.10 on port 8883.
1712345678: New client connected from 192.168.1.10 as sensor-main-building (p2, c1, k60).
```

## Certificate Validation Tests

| Test Scenario | Expected Result | Actual Result |
|---|---|---|
| Valid client certificate | ✅ Connection allowed | ✅ Connected |
| Missing client certificate | ❌ Connection rejected | ❌ Rejected |
| Untrusted CA certificate | ❌ Connection rejected | ❌ Rejected |
| Expired certificate | ❌ Connection rejected | ❌ Rejected |

## Gap Analysis

Identified the security gap between one-way TLS and mTLS, quantifying where one-way TLS is insufficient for production IoT deployments with untrusted networks.

## Artifacts

| File | Description |
|---|---|
| `Fabella_Terry-Secure_Your_Pipeline_with_mTLS.docx` | Certificate generation walkthrough and mTLS setup |
| `Fabella_Terry__Identity_Attack_Simulations.docx` | Attack simulation results across all certificate scenarios |
| `Fabella_Terry-_Identify_the_Gap_.docx` | Gap analysis worksheet comparing one-way TLS vs mTLS |

---

**Author:** Fabella Terry | AWS Certified Cloud Practitioner  
**Target Domain:** IAM Governance & GRC | IoT Security
