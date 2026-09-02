"""
Cryptography, PQC and Compliance Constants
Compliant with NIST PQC (FIPS 203/204/205), CycloneDX 1.6 CBOM, and DORA/NIS2 regulations.
"""

from enum import Enum
from typing import Dict, List, Set

# App Info
APP_NAME = "QuantumShield CBOM & Compliance Engine"
APP_VERSION = "1.0.0"
CYCLONEDX_VERSION = "1.6"

# PQC / Hybrid TLS Key Exchange Named Groups (draft-ietf-tls-hybrid-design)
# Used in ClientHello and ServerHello
PQC_HYBRID_GROUPS: Dict[int, Dict[str, str]] = {
    0x11EC: {
        "name": "X25519MLKEM768",
        "standard": "IETF draft-ietf-tls-hybrid-design / NIST FIPS 203",
        "status": "Production-Standard (Google Chrome, Cloudflare)",
        "security_level": "NIST Level 3 (AES-192 equivalent)",
        "is_quantum_safe": True
    },
    0x6399: {
        "name": "X25519Kyber768Draft00",
        "standard": "Legacy Draft / Pre-FIPS 203",
        "status": "Transitional (Earlier Kyber deployment)",
        "security_level": "NIST Level 3",
        "is_quantum_safe": True
    },
    0x11ED: {
        "name": "SecP256r1MLKEM768",
        "standard": "IETF draft / NIST FIPS 203",
        "status": "Standardizing",
        "security_level": "NIST Level 3",
        "is_quantum_safe": True
    },
    0x11EE: {
        "name": "X25519MLKEM1024",
        "standard": "IETF draft / NIST FIPS 203",
        "status": "Standardizing (High Security)",
        "security_level": "NIST Level 5 (AES-256 equivalent)",
        "is_quantum_safe": True
    }
}

# Classical Key Exchange Named Groups (Vulnerable to Shor's Algorithm)
CLASSICAL_NAMED_GROUPS: Dict[int, Dict[str, str]] = {
    0x001D: {"name": "x25519", "is_quantum_safe": False},
    0x0017: {"name": "secp256r1", "is_quantum_safe": False},
    0x0018: {"name": "secp384r1", "is_quantum_safe": False},
    0x0019: {"name": "secp521r1", "is_quantum_safe": False},
    0x001E: {"name": "x448", "is_quantum_safe": False},
    0x0100: {"name": "ffdhe2048", "is_quantum_safe": False},
    0x0101: {"name": "ffdhe3072", "is_quantum_safe": False},
    0x0102: {"name": "ffdhe4096", "is_quantum_safe": False},
}

# TLS Versions
class TLSVersion(str, Enum):
    SSLv2 = "SSLv2"
    SSLv3 = "SSLv3"
    TLSv1_0 = "TLSv1.0"
    TLSv1_1 = "TLSv1.1"
    TLSv1_2 = "TLSv1.2"
    TLSv1_3 = "TLSv1.3"

# Algorithm classifications
WEAK_HASH_ALGORITHMS: Set[str] = {"md5", "md2", "md4", "sha1", "sha-1"}
SECURE_HASH_ALGORITHMS: Set[str] = {"sha256", "sha-256", "sha384", "sha-384", "sha512", "sha-512", "sha3-256", "sha3-512"}

WEAK_CIPHERS: Set[str] = {"rc4", "des", "3des", "null", "export", "anon"}

# OID Dictionary for CycloneDX CBOM & Cert inspection
OID_MAP: Dict[str, str] = {
    "1.2.840.113549.1.1.1": "crypto/algorithm/rsa@PKCS1",
    "1.2.840.113549.1.1.11": "crypto/algorithm/sha256WithRSAEncryption@PKCS1",
    "1.2.840.113549.1.1.12": "crypto/algorithm/sha384WithRSAEncryption@PKCS1",
    "1.2.840.113549.1.1.13": "crypto/algorithm/sha512WithRSAEncryption@PKCS1",
    "1.2.840.10045.2.1": "crypto/algorithm/ecPublicKey@ANSI_X9.62",
    "1.2.840.10045.4.3.2": "crypto/algorithm/ecdsa-with-SHA256@ANSI_X9.62",
    "1.2.840.10045.4.3.3": "crypto/algorithm/ecdsa-with-SHA384@ANSI_X9.62",
    "1.2.840.10045.4.3.4": "crypto/algorithm/ecdsa-with-SHA512@ANSI_X9.62",
    "1.3.101.112": "crypto/algorithm/ed25519@RFC8410",
    "1.3.101.110": "crypto/algorithm/x25519@RFC8410",
    # Post-Quantum OIDs
    "2.16.840.1.101.3.4.4.2": "crypto/algorithm/ml-kem-768@NIST-FIPS-203",
    "2.16.840.1.101.3.4.4.3": "crypto/algorithm/ml-kem-1024@NIST-FIPS-203",
    "2.16.840.1.101.3.4.3.19": "crypto/algorithm/ml-dsa-65@NIST-FIPS-204",
    "2.16.840.1.101.3.4.3.20": "crypto/algorithm/ml-dsa-87@NIST-FIPS-204",
}

# DORA (Regulation EU 2022/2554) Articles Reference
DORA_CRITERIA = {
    "ART_9_1": {
        "title": "DORA Article 9(1) - Strong Encryption",
        "description": "Financial entities shall use cryptographic technologies and cipher suites based on leading international practices.",
        "weight": 25
    },
    "ART_9_2": {
        "title": "DORA Article 9(2) - Cryptographic Inventory & Key Management",
        "description": "Establishment of a Cryptography Bill of Materials (CBOM) detailing algorithms, key sizes, and certificate expiration.",
        "weight": 30
    },
    "ART_9_AGILITY": {
        "title": "DORA Crypto-Agility & Resilience",
        "description": "Readiness to migrate to post-quantum cryptographic standards to mitigate Harvest Now, Decrypt Later (HNDL) attacks.",
        "weight": 25
    },
    "SECURE_PROTOCOLS": {
        "title": "Secure Communication Channels (TLS 1.2+ / TLS 1.3)",
        "description": "Prohibition of legacy protocols (SSLv3, TLS 1.0, TLS 1.1) and deprecated ciphers.",
        "weight": 20
    }
}

# NIS2 (Directive EU 2022/2555) Articles Reference
NIS2_CRITERIA = {
    "ART_21_2_G": {
        "title": "NIS2 Article 21(2)(g) - Cryptography & Encryption Policies",
        "description": "Essential and important entities shall have policies and procedures regarding the use of cryptography and, where appropriate, encryption.",
        "weight": 50
    },
    "SUPPLY_CHAIN_SECURITY": {
        "title": "NIS2 Article 21(2)(d) - Supply Chain Cryptographic Verification",
        "description": "Assessing the security of third-party API endpoints and cryptographic integrity.",
        "weight": 50
    }
}
