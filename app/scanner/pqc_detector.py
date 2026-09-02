"""
Post-Quantum Cryptography (PQC) Hybrid Key Exchange Detector
Performs active network probing using TLS 1.3 ClientHello with PQC hybrid groups:
- X25519MLKEM768 (0x11ec) - IETF draft / NIST FIPS 203 (Google Chrome / Cloudflare standard)
- X25519Kyber768Draft00 (0x6399) - Legacy draft
- SecP256r1MLKEM768 (0x11ed)
"""

import socket
import ssl
import struct
from typing import Dict, Any, Optional
from app.core.constants import PQC_HYBRID_GROUPS, CLASSICAL_NAMED_GROUPS

class PQCDetector:
    """Probes a remote server for Post-Quantum TLS 1.3 Key Exchange support."""

    @staticmethod
    def craft_pqc_client_hello(hostname: str, supported_group_id: int = 0x11EC) -> bytes:
        """
        Constructs a minimal TLS 1.3 ClientHello record offering a PQC hybrid group.
        0x11EC = X25519MLKEM768 (NIST FIPS 203 hybrid)
        """
        # TLS Record Header: Type 0x16 (Handshake), Version 0x0301 (TLS 1.0 carrier), Length placeholder
        # Handshake Header: Type 0x01 (Client Hello), Length placeholder (3 bytes), Version 0x0303 (TLS 1.2 carrier)
        
        # 32 bytes random
        client_random = b"\x42" * 32
        
        # Session ID (32 bytes)
        session_id = b"\x00" * 32
        session_id_field = bytes([len(session_id)]) + session_id
        
        # Cipher suites: TLS_AES_128_GCM_SHA256 (0x1301), TLS_AES_256_GCM_SHA384 (0x1302), TLS_CHACHA20_POLY1305_SHA256 (0x1303)
        cipher_suites = b"\x13\x01\x13\x02\x13\x03\xc0\x2f\xc0\x30"
        cipher_suites_field = struct.pack(">H", len(cipher_suites)) + cipher_suites
        
        # Compression methods: null (0x00)
        compression = b"\x01\x00"
        
        # Extensions:
        extensions = bytearray()
        
        # 1. Server Name Indication (SNI) - type 0x0000
        server_name_bytes = hostname.encode("utf-8")
        sni_payload = (
            struct.pack(">H", len(server_name_bytes) + 3) +
            b"\x00" + # name_type: host_name
            struct.pack(">H", len(server_name_bytes)) +
            server_name_bytes
        )
        extensions.extend(b"\x00\x00" + struct.pack(">H", len(sni_payload)) + sni_payload)
        
        # 2. Supported Versions (TLS 1.3) - type 0x002b
        supported_versions = b"\x02\x03\x04" # length 2, TLS 1.3 (0x0304)
        extensions.extend(b"\x00\x2b" + struct.pack(">H", len(supported_versions)) + supported_versions)
        
        # 3. Supported Groups - type 0x000a
        # Include our target PQC group first, followed by fallback x25519 (0x001d) and secp256r1 (0x0017)
        groups_list = struct.pack(">HHHH", supported_group_id, 0x001D, 0x0017, 0x0018)
        groups_payload = struct.pack(">H", len(groups_list)) + groups_list
        extensions.extend(b"\x00\x0a" + struct.pack(">H", len(groups_payload)) + groups_payload)
        
        # 4. Signature Algorithms - type 0x000d
        sig_algs = b"\x04\x03\x08\x04\x04\x01\x05\x01\x06\x01" # ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, etc.
        sig_payload = struct.pack(">H", len(sig_algs)) + sig_algs
        extensions.extend(b"\x00\x0d" + struct.pack(">H", len(sig_payload)) + sig_payload)

        # 5. Key Share (TLS 1.3) - type 0x0033
        # Send key shares for the offered PQC group and fallback x25519
        pqc_share_len = 1216
        if supported_group_id == 0x11ED:
            pqc_share_len = 1249
        elif supported_group_id == 0x11EE:
            pqc_share_len = 1599

        dummy_pqc = b"\x01" * pqc_share_len
        entry_pqc = struct.pack(">HH", supported_group_id, len(dummy_pqc)) + dummy_pqc
        dummy_x25519 = b"\x02" * 32
        entry_x25519 = struct.pack(">HH", 0x001D, len(dummy_x25519)) + dummy_x25519
        shares = entry_pqc + entry_x25519
        ks_payload = struct.pack(">H", len(shares)) + shares
        extensions.extend(b"\x00\x33" + struct.pack(">H", len(ks_payload)) + ks_payload)

        # Extensions block
        extensions_field = struct.pack(">H", len(extensions)) + bytes(extensions)
        
        # Client Hello body
        client_hello_body = (
            b"\x03\x03" + # legacy version TLS 1.2
            client_random +
            session_id_field +
            cipher_suites_field +
            compression +
            extensions_field
        )
        
        # Handshake wrapper (type 0x01 = ClientHello)
        handshake_len = len(client_hello_body)
        handshake_header = bytes([0x01, (handshake_len >> 16) & 0xFF, (handshake_len >> 8) & 0xFF, handshake_len & 0xFF])
        handshake_message = handshake_header + client_hello_body
        
        # TLS Record wrapper (type 0x16 = Handshake, version 0x0301)
        record_header = struct.pack(">BHH", 0x16, 0x0301, len(handshake_message))
        return record_header + handshake_message

    @staticmethod
    def parse_server_hello_for_pqc(raw_response: bytes) -> Dict[str, Any]:
        """
        Parses ServerHello raw response to check which key_share / named group was selected.
        """
        result = {
            "pqc_supported": False,
            "selected_group": None,
            "group_name": "None / Classical Fallback",
            "is_hybrid": False,
            "details": "A szerver klasszikus (kvantum-sebezhető) kulcscserét használt, vagy elutasította a hibrid csoportot."
        }
        
        if len(raw_response) < 9:
            return result
            
        try:
            # Check for TLS record: 0x16 (Handshake), Handshake type: 0x02 (ServerHello)
            record_type, version, rec_len = struct.unpack(">BHH", raw_response[:5])
            if record_type != 0x16:
                return result
                
            handshake_type = raw_response[5]
            if handshake_type != 0x02: # ServerHello
                return result
                
            # Scan extensions in ServerHello
            # Skip: Handshake header (4 bytes) + version (2 bytes) + random (32 bytes)
            offset = 5 + 4 + 2 + 32
            if offset >= len(raw_response):
                return result
                
            # Session ID length
            session_id_len = raw_response[offset]
            offset += 1 + session_id_len
            
            # Cipher suite (2 bytes) + Compression (1 byte)
            offset += 2 + 1
            
            # Extensions length
            if offset + 2 > len(raw_response):
                return result
            ext_total_len = struct.unpack(">H", raw_response[offset:offset+2])[0]
            offset += 2
            
            ext_end = min(offset + ext_total_len, len(raw_response))
            while offset + 4 <= ext_end:
                ext_type, ext_len = struct.unpack(">HH", raw_response[offset:offset+4])
                offset += 4
                ext_data = raw_response[offset:offset+ext_len]
                offset += ext_len
                
                # Extension 0x0033: key_share in TLS 1.3
                if ext_type == 0x0033 and len(ext_data) >= 4:
                    selected_group = struct.unpack(">H", ext_data[:2])[0]
                    if selected_group in PQC_HYBRID_GROUPS:
                        group_info = PQC_HYBRID_GROUPS[selected_group]
                        return {
                            "pqc_supported": True,
                            "selected_group": hex(selected_group),
                            "group_name": group_info["name"],
                            "is_hybrid": True,
                            "security_level": group_info["security_level"],
                            "details": f"Aktív Post-Quantum Hibrid Kulcscsere detektálva! ({group_info['name']} - {group_info['standard']})"
                        }
                    elif selected_group in CLASSICAL_NAMED_GROUPS:
                        classical_info = CLASSICAL_NAMED_GROUPS[selected_group]
                        result["selected_group"] = hex(selected_group)
                        result["group_name"] = classical_info["name"]
                        result["details"] = f"Klasszikus kulcscsere kiválasztva ({classical_info['name']}). A szerver még nem alkalmaz PQC hibrid védelmet."
                        return result
        except Exception:
            pass

        return result

    @classmethod
    def probe_host(cls, host: str, port: int = 443, timeout: int = 5) -> Dict[str, Any]:
        """Probes remote host for X25519MLKEM768 / Kyber support."""
        for group_id, group_meta in PQC_HYBRID_GROUPS.items():
            try:
                probe_payload = cls.craft_pqc_client_hello(host, supported_group_id=group_id)
                with socket.create_connection((host, port), timeout=timeout) as s:
                    s.sendall(probe_payload)
                    s.settimeout(timeout)
                    resp = s.recv(4096)
                    parsed = cls.parse_server_hello_for_pqc(resp)
                    if parsed["pqc_supported"]:
                        return parsed
            except Exception:
                continue

        return {
            "pqc_supported": False,
            "selected_group": None,
            "group_name": "None",
            "is_hybrid": False,
            "details": "A célrendszer nem válaszolt a PQC hibrid kulcscsere felhívásokra (ML-KEM / Kyber hiányzik)."
        }
