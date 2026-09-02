"""
X.509 Certificate Chain Analyzer
Inspects certificate chains, public key parameters, signatures, and evaluates quantum resistance.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from app.core.constants import OID_MAP, WEAK_HASH_ALGORITHMS

class CertificateAnalyzer:
    @staticmethod
    def analyze_cert_bytes(cert_der: bytes) -> Dict[str, Any]:
        """Analyzes a DER-encoded X.509 certificate and returns detailed security metadata."""
        try:
            cert = x509.load_der_x509_certificate(cert_der)
            return CertificateAnalyzer.analyze_x509(cert)
        except Exception as e:
            return {"error": f"Failed to parse certificate: {str(e)}"}

    @staticmethod
    def analyze_x509(cert: x509.Certificate) -> Dict[str, Any]:
        """Extracts deep cryptographic attributes from an X.509 certificate."""
        now = datetime.now(timezone.utc)
        
        # Validity checks
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        is_expired = now > not_after
        is_not_yet_valid = now < not_before
        days_until_expiration = (not_after - now).days

        # Subject & Issuer
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        
        # Common Name extraction
        common_name = None
        for attr in cert.subject:
            if attr.oid == x509.NameOID.COMMON_NAME:
                common_name = attr.value
                break

        # Subject Alternative Names (SAN)
        san_list: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = [str(name.value) for name in san_ext.value]
        except Exception:
            pass

        # Public Key Analysis
        pub_key = cert.public_key()
        key_type = "Unknown"
        key_size_bits = 0
        curve_name = None
        is_quantum_safe = False
        quantum_vulnerability_reason = "Asymmetric key vulnerable to Shor's algorithm on Cryptographically Relevant Quantum Computers (CRQC)."

        if isinstance(pub_key, rsa.RSAPublicKey):
            key_type = "RSA"
            key_size_bits = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_type = "ECDSA"
            key_size_bits = pub_key.key_size
            curve_name = pub_key.curve.name
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            key_type = "Ed25519"
            key_size_bits = 256
        elif isinstance(pub_key, ed448.Ed448PublicKey):
            key_type = "Ed448"
            key_size_bits = 448
        elif isinstance(pub_key, dsa.DSAPublicKey):
            key_type = "DSA"
            key_size_bits = pub_key.key_size

        # Signature Algorithm
        sig_alg_name = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid.dotted_string)
        sig_hash_name = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "Unknown"
        
        # Weak signature hash detection (e.g. SHA-1)
        is_weak_signature = sig_hash_name.lower() in WEAK_HASH_ALGORITHMS

        # Compliance findings
        compliance_issues: List[str] = []
        if is_expired:
            compliance_issues.append("CRITICAL: Tanúsítvány lejárt!")
        elif days_until_expiration < 30:
            compliance_issues.append(f"WARNING: Tanúsítvány hamarosan lejár ({days_until_expiration} nap múlva)")

        if is_weak_signature:
            compliance_issues.append(f"CRITICAL: Elavult, sebezhető aláíró hash ({sig_hash_name})")

        if key_type == "RSA" and key_size_bits < 2048:
            compliance_issues.append(f"CRITICAL: DORA tiltott RSA kulcsméret (<2048 bit: {key_size_bits} bit)")
        elif key_type == "RSA" and key_size_bits == 2048:
            compliance_issues.append("INFO: RSA-2048 jelenleg még elfogadott, de 2026 után migrációra szorul.")

        # CycloneDX OID representation
        oid_ref = OID_MAP.get(cert.signature_algorithm_oid.dotted_string, f"crypto/algorithm/{sig_alg_name}")

        return {
            "common_name": common_name or subject,
            "subject": subject,
            "issuer": issuer,
            "serial_number": hex(cert.serial_number),
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_until_expiration": days_until_expiration,
            "is_expired": is_expired,
            "subject_alt_names": san_list,
            "key_type": key_type,
            "key_size_bits": key_size_bits,
            "curve_name": curve_name,
            "signature_algorithm": sig_alg_name,
            "signature_hash": sig_hash_name,
            "is_weak_signature": is_weak_signature,
            "is_quantum_safe": is_quantum_safe,
            "quantum_vulnerability_reason": quantum_vulnerability_reason,
            "compliance_issues": compliance_issues,
            "cyclonedx_ref": oid_ref
        }
