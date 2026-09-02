"""
Main Asynchronous TLS & Network Cryptography Scanner
Includes SSRF Protection, TLS Handshake analysis, Certificate extraction, and PQC evaluation.
"""

import ipaddress
import socket
import ssl
from typing import Dict, Any, Optional
from urllib.parse import urlparse

from app.core.config import settings
from app.scanner.cert_analyzer import CertificateAnalyzer
from app.scanner.pqc_detector import PQCDetector

class TLSScanner:
    """Performs deep cryptographic inspection of remote TLS endpoints."""

    @staticmethod
    def sanitize_and_resolve_target(target: str) -> Dict[str, Any]:
        """
        Extracts host & port, validates input, and performs SSRF protection checks.
        """
        cleaned = target.strip()
        if "://" in cleaned:
            parsed = urlparse(cleaned)
            hostname = parsed.hostname or cleaned
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        else:
            if ":" in cleaned:
                parts = cleaned.split(":")
                hostname = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    port = 443
            else:
                hostname = cleaned
                port = 443

        if not hostname:
            raise ValueError("Érvénytelen célpont: A domain vagy IP nem lehet üres.")

        # Resolve IP for SSRF validation
        try:
            resolved_ip = socket.gethostbyname(hostname)
        except socket.gaierror as e:
            raise ValueError(f"DNS feloldási hiba a célponthoz ({hostname}): {str(e)}")

        ip_obj = ipaddress.ip_address(resolved_ip)

        # SSRF Protection: Prevent scanning private, loopback, link-local, multicast addresses
        if not settings.allow_private_ip_scan:
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
                raise ValueError(
                    f"Biztonsági hiba (SSRF védelem): A(z) {hostname} ({resolved_ip}) belső hálózati cím, "
                    "amelynek szkennelése a vállalati biztonsági házirend szerint tiltott."
                )

        return {
            "hostname": hostname,
            "port": port,
            "resolved_ip": resolved_ip
        }

    @classmethod
    def scan_target(cls, target: str, timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Executes complete cryptographic audit of the target.
        """
        timeout_val = timeout or settings.default_timeout
        target_info = cls.sanitize_and_resolve_target(target)
        hostname = target_info["hostname"]
        port = target_info["port"]
        resolved_ip = target_info["resolved_ip"]

        scan_result: Dict[str, Any] = {
            "target": target,
            "hostname": hostname,
            "port": port,
            "resolved_ip": resolved_ip,
            "success": False,
            "tls_info": {},
            "certificate_info": {},
            "pqc_info": {},
            "errors": []
        }

        # 1. Standard TLS Handshake & Cert Extraction
        context = ssl.create_default_context()
        # Allow inspection even if self-signed, but note verification status
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((resolved_ip, port), timeout=timeout_val) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cipher_info = ssock.cipher()
                    version = ssock.version()
                    alpn = ssock.selected_alpn_protocol()
                    compression = ssock.compression()

                    scan_result["tls_info"] = {
                        "version": version,
                        "cipher_name": cipher_info[0] if cipher_info else "Unknown",
                        "cipher_protocol": cipher_info[1] if cipher_info else "Unknown",
                        "cipher_bits": cipher_info[2] if cipher_info else 0,
                        "alpn_protocol": alpn or "None",
                        "compression": compression or "None",
                        "is_tls13": version == "TLSv1.3",
                        "is_tls12": version == "TLSv1.2",
                        "is_legacy_tls": version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2")
                    }

                    if cert_der:
                        scan_result["certificate_info"] = CertificateAnalyzer.analyze_cert_bytes(cert_der)
                    else:
                        scan_result["errors"].append("Nem sikerült lekérni a tanúsítványt (üres válasz).")

                    scan_result["success"] = True

        except Exception as e:
            scan_result["errors"].append(f"TLS kézfogás hiba: {str(e)}")
            return scan_result

        # 2. Post-Quantum Hybrid TLS Probing
        try:
            pqc_result = PQCDetector.probe_host(hostname, port=port, timeout=timeout_val)
            scan_result["pqc_info"] = pqc_result
        except Exception as e:
            scan_result["pqc_info"] = {
                "pqc_supported": False,
                "error": f"PQC szonda hiba: {str(e)}"
            }

        return scan_result
