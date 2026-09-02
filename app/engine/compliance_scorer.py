"""
Compliance & Risk Scorer for DORA, NIS2, and Quantum Resilience
Calculates regulatory compliance indices, audit findings, and concrete remediation steps.
"""

from typing import Dict, Any, List
from app.core.constants import DORA_CRITERIA, NIS2_CRITERIA, WEAK_CIPHERS

class ComplianceScorer:
    """Evaluates scan results against European regulations (DORA, NIS2) and PQC standards."""

    @classmethod
    def evaluate(cls, scan_result: Dict[str, Any], hndl_info: Dict[str, Any]) -> Dict[str, Any]:
        tls_info = scan_result.get("tls_info", {})
        cert_info = scan_result.get("certificate_info", {})
        pqc_info = scan_result.get("pqc_info", {})

        version = tls_info.get("version", "")
        cipher_name = tls_info.get("cipher_name", "").lower()
        key_type = cert_info.get("key_type", "")
        key_size = cert_info.get("key_size_bits", 0)
        is_expired = cert_info.get("is_expired", False)
        is_weak_sig = cert_info.get("is_weak_signature", False)
        pqc_supported = pqc_info.get("pqc_supported", False)

        remediation_steps: List[Dict[str, str]] = []
        dora_breakdown: Dict[str, int] = {}

        # 1. DORA Score Calculation
        # ART_9_1: Strong Encryption (Max 25)
        enc_score = 25
        if any(w in cipher_name for w in WEAK_CIPHERS):
            enc_score = 0
            remediation_steps.append({
                "severity": "CRITICAL",
                "title": "Gyenge titkosító algoritmus (Cipher)",
                "action": "Tiltsa le a régebbi, gyenge titkosítókat (pl. RC4, 3DES, CBC módok), használjon kizárólag AEAD (AES-GCM vagy ChaCha20-Poly1305) titkosítást!"
            })
        elif not tls_info.get("is_tls13") and not tls_info.get("is_tls12"):
            enc_score = 5
        elif tls_info.get("is_tls13"):
            enc_score = 25
        else: # TLS 1.2
            enc_score = 20
        dora_breakdown["strong_encryption"] = enc_score

        # ART_9_2: Cryptographic Inventory & Key Management (Max 30)
        inv_score = 30
        if is_expired:
            inv_score -= 25
            remediation_steps.append({
                "severity": "CRITICAL",
                "title": "Lejárt X.509 Tanúsítvány",
                "action": "Azonnal újítsa meg a szerver tanúsítványát! A DORA és az MNB felügyelet azonnali büntetést szabhat ki lejárt cert-ért."
            })
        if is_weak_sig:
            inv_score -= 20
            remediation_steps.append({
                "severity": "CRITICAL",
                "title": "Sebezhető Aláíró Hash (SHA-1/MD5)",
                "action": "A tanúsítványt le kell cserélni legalább SHA-256 vagy SHA-384 alapú digitális aláírással ellátott tanúsítványra."
            })
        if key_type == "RSA" and key_size < 2048:
            inv_score -= 20
            remediation_steps.append({
                "severity": "CRITICAL",
                "title": "Elégtelen RSA kulcsméret (< 2048 bit)",
                "action": "A jelenlegi kulcsméret nem felel meg a biztonsági előírásoknak. Váltson legalább RSA-3072 vagy ECDSA P-256 kulcsra."
            })
        dora_breakdown["key_management"] = max(0, inv_score)

        # ART_9_AGILITY: Crypto-Agility & PQC (Max 25)
        agility_score = 10 # Baseline for standard TLS 1.3
        if pqc_supported:
            agility_score = 25
        elif tls_info.get("is_tls13"):
            agility_score = 15
            remediation_steps.append({
                "severity": "MEDIUM",
                "title": "Poszt-Kvantum (PQC) Hibrid Kézfogás Hiánya",
                "action": "Engedélyezze a hibrid X25519MLKEM768 kulcscserét a peremhálózaton a HNDL (adatlopás és későbbi visszafejtés) kivédésére."
            })
        else:
            agility_score = 5
            remediation_steps.append({
                "severity": "HIGH",
                "title": "Hiányzó Kripto-Agilitás",
                "action": "A rendszer nem támogatja a modern kulcscserét, ami ellehetetleníti a kvantumbiztos szabványokra való áttérést."
            })
        dora_breakdown["crypto_agility"] = agility_score

        # SECURE_PROTOCOLS: (Max 20)
        proto_score = 20
        if tls_info.get("is_legacy_tls"):
            proto_score = 0
            remediation_steps.append({
                "severity": "CRITICAL",
                "title": "Elavult TLS verzió használatban",
                "action": "Tiltsa le a TLS 1.0 és TLS 1.1 protokollokat a kiszolgálón!"
            })
        elif tls_info.get("is_tls13"):
            proto_score = 20
        elif tls_info.get("is_tls12"):
            proto_score = 16
        else:
            proto_score = 0
        dora_breakdown["secure_protocols"] = proto_score

        total_dora_score = sum(dora_breakdown.values())

        # 2. NIS2 Score Calculation
        nis2_score = int(total_dora_score * 0.95)
        if pqc_supported:
            nis2_score = min(100, nis2_score + 5)

        # 3. Quantum Resilience Score (PQC Score)
        if pqc_supported:
            quantum_resilience_score = 95
        elif tls_info.get("is_tls13") and key_size >= 2048:
            quantum_resilience_score = 45 # Prepared for TLS 1.3, but no PQC groups
        elif tls_info.get("is_tls12"):
            quantum_resilience_score = 30
        else:
            quantum_resilience_score = 10

        # Grade
        if total_dora_score >= 90 and pqc_supported:
            grade = "A+ (Kvantumbiztos)"
            audit_status = "MEGFELELT (Kiváló)"
        elif total_dora_score >= 80:
            grade = "A (DORA Kompatibilis)"
            audit_status = "MEGFELELT (PQC migráció ajánlott)"
        elif total_dora_score >= 65:
            grade = "B (Feltételesen Megfelelt)"
            audit_status = "HIÁNYOSSÁGOK DETEKTÁLVA"
        elif total_dora_score >= 50:
            grade = "C (Szabályozói Kockázat)"
            audit_status = "NEM MEGFELELŐ"
        else:
            grade = "F (Kritikus Audit Bukás)"
            audit_status = "AZONNALI BÍRSÁGVESZÉLY"

        # --- BŐVÍTETT AUDIT ADATOK ---

        # Executive Summary (CISO/CFO szintű összefoglaló)
        critical_count = sum(1 for r in remediation_steps if r["severity"] == "CRITICAL")
        high_count = sum(1 for r in remediation_steps if r["severity"] == "HIGH")
        medium_count = sum(1 for r in remediation_steps if r["severity"] == "MEDIUM")

        if total_dora_score >= 90 and pqc_supported:
            executive_summary = (
                f"A vizsgált rendszer kiváló biztonsági állapotban van (DORA pontszám: {total_dora_score}/100). "
                f"A poszt-kvantum hibrid kézfogás (PQC) aktív, amely hatékonyan védi az adatokat a jövőbeli "
                f"kvantumszámítógépes támadásoktól (HNDL). A rendszer megfelel a DORA és NIS2 szabályozási követelményeknek. "
                f"Javasolt a jelenlegi biztonsági szint fenntartása és a kriptográfiai leltár (CBOM) rendszeres frissítése."
            )
        elif total_dora_score >= 65:
            executive_summary = (
                f"A vizsgált rendszer részlegesen megfelel a szabályozási követelményeknek (DORA pontszám: {total_dora_score}/100). "
                f"Összesen {critical_count} kritikus és {high_count} magas súlyosságú megállapítás azonosítva. "
                f"A legfontosabb hiányosság a poszt-kvantum kriptográfia (PQC) hiánya, amely HNDL támadásnak teszi ki a rendszert. "
                f"A DORA 9. cikk szerinti teljes megfeleléshez a remediation lépések végrehajtása szükséges 90 napon belül."
            )
        else:
            executive_summary = (
                f"A vizsgált rendszer SÚLYOS BIZTONSÁGI HIÁNYOSSÁGOKAT mutat (DORA pontszám: {total_dora_score}/100). "
                f"{critical_count} kritikus, {high_count} magas és {medium_count} közepes súlyosságú megállapítás azonosítva. "
                f"A rendszer jelenlegi állapotában nem felel meg a DORA és NIS2 követelményeknek, és azonnali szabályozói "
                f"bírságveszélynek van kitéve. Azonnali remediációs terv kidolgozása és végrehajtása szükséges."
            )

        # Risk Register
        risk_register = []
        risk_counter = 1

        if is_expired:
            risk_register.append({
                "id": f"RISK-{risk_counter:03d}",
                "category": "Tanúsítványkezelés",
                "finding": "A szerver X.509 tanúsítványa lejárt, amely azonnali szolgáltatáskiesést és biztonsági rést jelent.",
                "impact": "MAGAS",
                "regulation": "DORA 9(2) – Kriptográfiai leltár és kulcskezelés",
                "recommendation": "Azonnal újítsa meg a tanúsítványt egy megbízható CA-tól, és vezessen be automatikus cert-megújítási folyamatot (pl. ACME/Let's Encrypt)."
            })
            risk_counter += 1

        if is_weak_sig:
            risk_register.append({
                "id": f"RISK-{risk_counter:03d}",
                "category": "Kriptográfiai",
                "finding": "A tanúsítvány gyenge hash algoritmust (SHA-1 vagy MD5) használ az aláíráshoz, amely ütközéses támadásnak kitett.",
                "impact": "MAGAS",
                "regulation": "DORA 9(1) – Erős titkosítás követelménye",
                "recommendation": "Cserélje le a tanúsítványt SHA-256 vagy SHA-384 alapú aláírással ellátottra."
            })
            risk_counter += 1

        if key_type == "RSA" and key_size < 2048:
            risk_register.append({
                "id": f"RISK-{risk_counter:03d}",
                "category": "Kriptográfiai",
                "finding": f"Az RSA kulcsméret ({key_size} bit) nem felel meg a minimális biztonsági követelményeknek (2048 bit).",
                "impact": "MAGAS",
                "regulation": "DORA 9(1) – Nemzetközi legjobb gyakorlatok szerinti titkosítás",
                "recommendation": "Váltson legalább RSA-3072 vagy ECDSA P-256 kulcsra."
            })
            risk_counter += 1

        if any(w in cipher_name for w in WEAK_CIPHERS):
            risk_register.append({
                "id": f"RISK-{risk_counter:03d}",
                "category": "Titkosítás",
                "finding": f"Gyenge titkosítási algoritmus detektálva a TLS konfigurációban: '{tls_info.get('cipher_name', '')}'.",
                "impact": "MAGAS",
                "regulation": "DORA 9(1) – Erős titkosítás, NIS2 21(2)(g) – Titkosítási szabályzat",
                "recommendation": "Csak AEAD alapú cipher suite-okat engedélyezzen (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)."
            })
            risk_counter += 1

        if tls_info.get("is_legacy_tls"):
            risk_register.append({
                "id": f"RISK-{risk_counter:03d}",
                "category": "Protokoll",
                "finding": f"Elavult TLS protokollverzió használatban ({version}), amely ismert sebezhetőségeknek kitett.",
                "impact": "MAGAS",
                "regulation": "DORA – Biztonságos kommunikációs csatornák",
                "recommendation": "Tiltsa le a TLS 1.0 és TLS 1.1 protokollokat, és engedélyezze kizárólag a TLS 1.2+ / TLS 1.3-at."
            })
            risk_counter += 1

        if not pqc_supported:
            risk_register.append({
                "id": f"RISK-{risk_counter:03d}",
                "category": "Kvantumkockázat",
                "finding": "A szerver nem támogatja a poszt-kvantum (PQC) hibrid kulcscserét, HNDL támadásnak kitett.",
                "impact": "KÖZEPES" if tls_info.get("is_tls13") else "MAGAS",
                "regulation": "DORA 9 – Kripto-agilitás, NIST IR 8547 – PQC átállás",
                "recommendation": "Engedélyezze a X25519MLKEM768 hibrid kulcscserét a TLS 1.3 konfiguráción belül."
            })
            risk_counter += 1

        # Certificate Security Assessment
        if key_type == "RSA":
            if key_size >= 4096:
                key_strength_verdict = f"ERŐS – RSA-{key_size} megfelel a hosszútávú biztonsági követelményeknek."
            elif key_size >= 2048:
                key_strength_verdict = f"ELFOGADHATÓ – RSA-{key_size} jelenleg megfelel, de RSA-3072+ ajánlott."
            else:
                key_strength_verdict = f"GYENGE – RSA-{key_size} nem felel meg a minimális biztonsági szintnek (min. 2048 bit)."
        elif key_type in ("ECDSA", "Ed25519"):
            if key_size >= 256:
                key_strength_verdict = f"ERŐS – {key_type}-{key_size} hatékony és biztonságos kulcsméret."
            else:
                key_strength_verdict = f"GYENGE – {key_type}-{key_size} nem felel meg a minimális biztonsági követelményeknek."
        else:
            key_strength_verdict = f"ISMERETLEN – '{key_type}' kulcstípus nem szabványos, felülvizsgálat szükséges."

        sig_algo = cert_info.get("signature_algorithm", "N/A")
        if is_weak_sig:
            sig_verdict = f"SEBEZHETŐ – A(z) '{sig_algo}' aláíró algoritmus (SHA-1/MD5) ütközéses támadásnak kitett."
        else:
            sig_verdict = f"MEGFELELŐ – A(z) '{sig_algo}' aláíró algoritmus megfelel a biztonsági követelményeknek."

        days_until_exp = cert_info.get("days_until_expiration", 0)
        if is_expired:
            expiration_risk = f"KRITIKUS – A tanúsítvány LEJÁRT ({abs(days_until_exp)} napja). Azonnali csere szükséges."
        elif days_until_exp < 30:
            expiration_risk = f"MAGAS – A tanúsítvány {days_until_exp} napon belül lejár. Sürgős megújítás szükséges."
        elif days_until_exp < 90:
            expiration_risk = f"KÖZEPES – A tanúsítvány {days_until_exp} napon belül lejár. Tervezett megújítás ajánlott."
        else:
            expiration_risk = f"ALACSONY – A tanúsítvány {days_until_exp} nap múlva jár le."

        chain_valid = cert_info.get("chain_valid", None)
        if chain_valid is True:
            chain_status = "ÉRVÉNYES – A tanúsítványlánc teljes és megbízható gyökér CA-hoz vezet."
        elif chain_valid is False:
            chain_status = "HIBÁS – A tanúsítványlánc hiányos vagy nem megbízható CA-hoz vezet."
        else:
            chain_status = "NEM ELLENŐRZÖTT – A tanúsítványlánc validálása nem történt meg ebben a vizsgálatban."

        if pqc_supported:
            quantum_vulnerability = "VÉDETT – Hibrid PQC kulcscsere aktív, a tanúsítvány kvantumbiztos csatornán keresztül kerül kézbesítésre."
        elif key_type == "RSA":
            quantum_vulnerability = f"SEBEZHETŐ – Az RSA-{key_size} kulcs Shor-algoritmussal feltörhető kvantumszámítógéppel (CRQC, ~2029-2033)."
        elif key_type in ("ECDSA", "Ed25519"):
            quantum_vulnerability = f"SEBEZHETŐ – A(z) {key_type} kulcs Shor-algoritmussal feltörhető kvantumszámítógéppel."
        else:
            quantum_vulnerability = "ISMERETLEN – Nem szabványos kulcstípus, kvantum-kockázat nem meghatározható."

        cert_security_assessment = {
            "chain_status": chain_status,
            "key_strength_verdict": key_strength_verdict,
            "signature_algorithm_verdict": sig_verdict,
            "expiration_risk": expiration_risk,
            "quantum_vulnerability": quantum_vulnerability
        }

        # TLS Security Assessment
        if tls_info.get("is_tls13"):
            protocol_verdict = "KIVÁLÓ – TLS 1.3 a legmodernebb és legbiztonságosabb protokollverzió."
        elif tls_info.get("is_tls12"):
            protocol_verdict = "ELFOGADHATÓ – TLS 1.2 biztonságos megfelelő cipher suite konfigurációval, de TLS 1.3 ajánlott."
        elif tls_info.get("is_legacy_tls"):
            protocol_verdict = f"KRITIKUS – Elavult protokoll ({version}) használatban, ismert sebezhetőségek (BEAST, POODLE, DROWN)."
        else:
            protocol_verdict = f"ISMERETLEN – '{version}' protokollverzió nem felismert."

        if any(w in cipher_name for w in WEAK_CIPHERS):
            cipher_strength_verdict = f"GYENGE – A '{tls_info.get('cipher_name', '')}' cipher suite elavult és sebezhető."
        elif "gcm" in cipher_name or "chacha20" in cipher_name:
            cipher_strength_verdict = f"ERŐS – A '{tls_info.get('cipher_name', '')}' AEAD cipher suite megfelel a legjobb gyakorlatoknak."
        else:
            cipher_strength_verdict = f"ELFOGADHATÓ – A '{tls_info.get('cipher_name', '')}' cipher suite használható, de AEAD ajánlott."

        if tls_info.get("is_tls13"):
            forward_secrecy = "BIZTOSÍTOTT – A TLS 1.3 kizárólag forward secrecy-t támogató kulcscserét engedélyez (DHE/ECDHE)."
        elif "ecdhe" in cipher_name or "dhe" in cipher_name:
            forward_secrecy = "BIZTOSÍTOTT – ECDHE/DHE kulcscsere aktív, a munkamenetkulcsok nem rekonstruálhatók utólag."
        else:
            forward_secrecy = "HIÁNYZIK – Forward secrecy nélkül a szerver privát kulcsának kompromittálása az összes korábbi forgalom visszafejtését lehetővé teszi."

        compression_risk = "ALACSONY – TLS tömörítés alapértelmezetten letiltva a modern konfigurációkban (CRIME támadás ellen)."

        if tls_info.get("is_tls13"):
            downgrade_resistance = "BIZTOSÍTOTT – TLS 1.3 beépített downgrade sentinel értékeket tartalmaz (RFC 8446 §4.1.3)."
        elif tls_info.get("is_tls12"):
            downgrade_resistance = "RÉSZLEGES – TLS 1.2 downgrade-védelme szerver konfigurációtól függ. TLS_FALLBACK_SCSV ajánlott."
        else:
            downgrade_resistance = "HIÁNYZIK – Az elavult protokoll nem véd a downgrade támadások ellen."

        tls_security_assessment = {
            "protocol_verdict": protocol_verdict,
            "cipher_strength_verdict": cipher_strength_verdict,
            "forward_secrecy": forward_secrecy,
            "compression_risk": compression_risk,
            "downgrade_resistance": downgrade_resistance
        }

        # Regulatory Timeline
        regulatory_timeline = [
            {"date": "2023-01-16", "regulation": "DORA", "event": "DORA (EU 2022/2554) rendelet hatályba lépése", "status": "HATÁLYOS"},
            {"date": "2025-01-17", "regulation": "DORA", "event": "DORA alkalmazási kötelezettség kezdete – pénzügyi szervezetek kriptográfiai megfelelése kötelező", "status": "HATÁLYOS"},
            {"date": "2024-10-18", "regulation": "NIS2", "event": "NIS2 (EU 2022/2555) irányelv átültetési határideje a tagállamok számára", "status": "HATÁLYOS"},
            {"date": "2024-08-13", "regulation": "NIST PQC", "event": "NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) véglegesítése", "status": "HATÁLYOS"},
            {"date": "2025-09-01", "regulation": "NIST PQC", "event": "NIST IR 8547 – Átállás a poszt-kvantum kriptográfiai szabványokra", "status": "HATÁLYOS"},
            {"date": "2030-12-31", "regulation": "NIST PQC", "event": "NIST ajánlott határidő: klasszikus kriptográfia fokozatos kivezetése megkezdése", "status": "KÖZELGŐ"},
            {"date": "2035-12-31", "regulation": "NIST PQC", "event": "NIST cél: RSA-2048 és 112-bites ECC kivezetése", "status": "TERVEZETT"}
        ]

        # Benchmark Comparison
        if total_dora_score >= 90:
            percentile = 95
            better_than = "a pénzügyi szektor szervezeteinek 95%-ánál jobb"
        elif total_dora_score >= 75:
            percentile = 70
            better_than = "a pénzügyi szektor szervezeteinek 70%-ánál jobb"
        elif total_dora_score >= 50:
            percentile = 40
            better_than = "a pénzügyi szektor szervezeteinek 40%-ánál jobb"
        else:
            percentile = 10
            better_than = "a pénzügyi szektor szervezeteinek mindössze 10%-ánál jobb – a legalsó kategóriában"

        benchmark_comparison = {
            "percentile": percentile,
            "better_than": better_than,
            "industry_avg_dora_score": 62
        }

        # Mosca Theorem (a hndl_info-ból emelünk ki)
        mosca_x = hndl_info.get("mosca_x", 0)
        mosca_y = hndl_info.get("mosca_y", 0)
        mosca_z = hndl_info.get("mosca_z", 0)
        mosca_sum = mosca_x + mosca_y
        inequality_holds = mosca_sum > mosca_z

        if inequality_holds:
            formula_str = f"X({mosca_x}) + Y({mosca_y}) = {mosca_sum} > Z({mosca_z}) → AZONNALI MIGRÁCIÓ SZÜKSÉGES"
        else:
            formula_str = f"X({mosca_x}) + Y({mosca_y}) = {mosca_sum} ≤ Z({mosca_z}) → NINCS AZONNALI KVANTUMKITETTSÉG"

        mosca_theorem = {
            "x_data_shelf_life": mosca_x,
            "y_migration_time": mosca_y,
            "z_crqc_eta": mosca_z,
            "inequality_holds": inequality_holds,
            "formula": formula_str
        }

        return {
            "dora_score": total_dora_score,
            "dora_breakdown": dora_breakdown,
            "nis2_score": nis2_score,
            "quantum_resilience_score": quantum_resilience_score,
            "grade": grade,
            "audit_status": audit_status,
            "hndl_risk": hndl_info,
            "remediation_steps": remediation_steps,
            "pqc_deployed": pqc_supported,
            "executive_summary": executive_summary,
            "risk_register": risk_register,
            "cert_security_assessment": cert_security_assessment,
            "tls_security_assessment": tls_security_assessment,
            "regulatory_timeline": regulatory_timeline,
            "benchmark_comparison": benchmark_comparison,
            "mosca_theorem": mosca_theorem
        }

