"""
CycloneDX 1.6 Cryptography Bill of Materials (CBOM) Generator
Produces compliant CycloneDX 1.6 JSON documents containing full cryptographic inventories.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List
from app.core.constants import APP_NAME, APP_VERSION, CYCLONEDX_VERSION

class CBOMGenerator:
    """Generates official CycloneDX 1.6 CBOM document from audit scan data."""

    @classmethod
    def generate(cls, scan_result: Dict[str, Any], compliance_result: Dict[str, Any]) -> Dict[str, Any]:
        hostname = scan_result.get("hostname", "unknown-target")
        tls_info = scan_result.get("tls_info", {})
        cert_info = scan_result.get("certificate_info", {})
        pqc_info = scan_result.get("pqc_info", {})

        serial_number = f"urn:uuid:{uuid.uuid4()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        components: List[Dict[str, Any]] = []

        # 1. Protocol Component (TLS)
        tls_version = tls_info.get("version", "TLS")
        cipher_name = tls_info.get("cipher_name", "Unknown")
        protocol_bom_ref = f"crypto/protocol/tls@{tls_version}"

        components.append({
            "type": "cryptographic-asset",
            "name": f"Protocol: {tls_version}",
            "bom-ref": protocol_bom_ref,
            "description": f"Hálózati átviteli biztonsági protokoll ({hostname})",
            "cryptoProperties": {
                "assetType": "protocol",
                "protocolProperties": {
                    "type": "tls",
                    "version": tls_version.replace("TLSv", ""),
                    "cipherSuites": [
                        {
                            "name": cipher_name,
                            "algorithms": [
                                "crypto/algorithm/aes-gcm",
                                "crypto/algorithm/key-exchange"
                            ]
                        }
                    ]
                }
            }
        })

        # 2. Key Exchange Component (PQC or Classical)
        is_pqc = pqc_info.get("pqc_supported", False)
        group_name = pqc_info.get("group_name", "ECDHE-Classical")
        ke_bom_ref = f"crypto/algorithm/{group_name.lower()}"

        components.append({
            "type": "cryptographic-asset",
            "name": f"KeyExchange: {group_name}",
            "bom-ref": ke_bom_ref,
            "description": "Munkamenet-kulcscsere algoritmus",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "key-exchange",
                    "parameterSetIdentifier": group_name
                },
                "quantumProperties": {
                    "isQuantumSafe": is_pqc,
                    "quantumSecurityLevel": 3 if is_pqc else 0,
                    "mitigationStatus": "Protected (Hybrid PQC)" if is_pqc else "Vulnerable to Shor's Algorithm"
                }
            }
        })

        # 3. Certificate Component
        if cert_info and not cert_info.get("error"):
            cert_bom_ref = f"crypto/certificate/{cert_info.get('fingerprint_sha256', 'cert')[:16]}"
            components.append({
                "type": "cryptographic-asset",
                "name": f"Certificate: {cert_info.get('common_name', hostname)}",
                "bom-ref": cert_bom_ref,
                "description": f"X.509 Kiszolgáló tanúsítvány (Kibocsátó: {cert_info.get('issuer', 'Unknown')})",
                "cryptoProperties": {
                    "assetType": "certificate",
                    "certificateProperties": {
                        "subjectName": cert_info.get("subject"),
                        "issuerName": cert_info.get("issuer"),
                        "notValidBefore": cert_info.get("not_before"),
                        "notValidAfter": cert_info.get("not_after"),
                        "signatureAlgorithmRef": cert_info.get("cyclonedx_ref"),
                        "subjectAlternativeNames": cert_info.get("subject_alt_names", [])
                    },
                    "quantumProperties": {
                        "isQuantumSafe": cert_info.get("is_quantum_safe", False),
                        "quantumSecurityLevel": 0,
                        "mitigationStatus": "Vulnerable to Shor's Algorithm"
                    }
                }
            })

            # 4. Public Key Algorithm of Certificate
            pub_key_type = cert_info.get("key_type", "Unknown")
            pub_key_size = cert_info.get("key_size_bits", 0)
            components.append({
                "type": "cryptographic-asset",
                "name": f"PublicKey: {pub_key_type}-{pub_key_size}",
                "bom-ref": f"crypto/algorithm/{pub_key_type.lower()}@{pub_key_size}",
                "description": f"Tanúsítvány aszimmetrikus nyilvános kulcsa ({pub_key_size} bit)",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "public-key",
                        "parameterSetIdentifier": f"{pub_key_type}-{pub_key_size}"
                    },
                    "quantumProperties": {
                        "isQuantumSafe": False,
                        "quantumSecurityLevel": 0,
                        "mitigationStatus": "Shor-vulnerable"
                    }
                }
            })

        # Assemble Complete CycloneDX 1.6 Document
        cbom_document: Dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": CYCLONEDX_VERSION,
            "serialNumber": serial_number,
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": [
                    {
                        "vendor": "QuantumShield Security",
                        "name": APP_NAME,
                        "version": APP_VERSION
                    }
                ],
                "component": {
                    "type": "service",
                    "name": hostname,
                    "description": f"Kriptográfiai audit célpont: {hostname}:{scan_result.get('port', 443)}"
                },
                "properties": [
                    {"name": "quantumshield:dora_score", "value": str(compliance_result.get("dora_score", 0))},
                    {"name": "quantumshield:nis2_score", "value": str(compliance_result.get("nis2_score", 0))},
                    {"name": "quantumshield:audit_grade", "value": compliance_result.get("grade", "N/A")},
                    {"name": "quantumshield:hndl_risk", "value": compliance_result.get("hndl_risk", {}).get("risk_level", "UNKNOWN")}
                ]
            },
            "components": components
        }

        return cbom_document
