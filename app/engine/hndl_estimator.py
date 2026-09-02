"""
Harvest Now, Decrypt Later (HNDL) Risk Estimator
Evaluates the exposure window of encrypted data against future Cryptographically Relevant Quantum Computers (CRQC).
"""

from typing import Dict, Any

class HNDLEstimator:
    """Calculates HNDL exposure score and Moscha's Theorem risk window."""

    @staticmethod
    def calculate_hndl_risk(tls_info: Dict[str, Any], cert_info: Dict[str, Any], pqc_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Mosca's Theorem: If X (shelf life of data) + Y (migration time) > Z (time to CRQC), then collapse is inevitable.
        """
        pqc_supported = pqc_info.get("pqc_supported", False)
        tls_version = tls_info.get("version", "")
        key_type = cert_info.get("key_type", "")
        key_size = cert_info.get("key_size_bits", 0)

        # Baseline risk rating
        if pqc_supported:
            risk_level = "LOW"
            exposure_score = 15 # 0-100 (lower is better)
            status_text = "Védett: A hibrid PQC kézfogás védi a továbbított adatokat a jövőbeli kvantumfejtéstől."
            shelf_life_safe_years = 30
            mosca_x = 15
            mosca_y = 1
            mosca_z = 7
            hndl_scenario = (
                "A szerver hibrid PQC (ML-KEM-768) kulcscserét alkalmaz, így a TLS munkamenet kulcsok "
                "kvantumszámítógéppel sem fejthetők vissza. A 'Harvest Now, Decrypt Later' támadási vektor "
                "hatékonyan semlegesítve van, mivel a lehallgatott titkosított forgalom a jövőben sem lesz visszafejthető."
            )
            affected_data_types = ["Védett: PQC hibrid kézfogás aktív"]
            estimated_financial_impact = "Minimális – a kvantumkockázat megfelelően kezelve van."
        else:
            # Classical crypto only
            exposure_score = 85
            is_weak_key = (key_type == "RSA" and key_size < 2048) or (key_type in ("ECDSA", "Ed25519") and key_size < 256)
            if tls_version in ("TLSv1", "TLSv1.1", "SSLv3") or is_weak_key:
                risk_level = "CRITICAL"
                exposure_score = 98
                status_text = "KRITIKUS KOCKÁZAT: Az elavult kriptográfia és a PQC hiánya miatt a forgalom már ma is könnyen sebezhető."
                shelf_life_safe_years = 0
                mosca_x = 25
                mosca_y = 5
                mosca_z = 4
                hndl_scenario = (
                    "KRITIKUS FORGATÓKÖNYV: A szerver elavult TLS protokollt és/vagy gyenge kulcsot használ. "
                    "Egy állami szintű támadó (APT) a hálózati forgalmat már most passzívan rögzítheti minimális "
                    "erőforrással. Az adatok a jelenlegi kriptográfiával sem feltétlenül biztonságosak, és a "
                    "kvantumszámítógépek megjelenésével (CRQC, ~2029-2033) a rögzített forgalom teljes egészében "
                    "visszafejthető lesz. Az elavult protokoll ráadásul aktív támadásoknak (BEAST, POODLE, DROWN) is kitett."
                )
                affected_data_types = [
                    "Banki tranzakciók és fizetési adatok",
                    "Ügyfélazonosító adatok (PII)",
                    "API hitelesítő tokenek és munkamenetkulcsok",
                    "Belső hálózati kommunikáció",
                    "Hitelkártya adatok (PCI DSS hatókör)",
                    "Egészségügyi adatok (ha releváns)"
                ]
                estimated_financial_impact = (
                    "Kritikus – becsült kár: €5M - €50M+ (GDPR bírság: éves árbevétel 4%-a, "
                    "DORA bírság: max. €10M vagy árbevétel 5%-a, reputációs kár, ügyfelek elvesztése)."
                )
            elif key_type in ("RSA", "ECDSA", "Ed25519"):
                risk_level = "HIGH"
                exposure_score = 85
                status_text = (
                    "MAGAS HNDL KOCKÁZAT: A forgalmat ma lehallgató támadók a jövőbeli "
                    "kvantumszámítógéppel (CRQC) 2029-2033 között minden rögzített adatot visszamenőleg dekódolni tudnak."
                )
                shelf_life_safe_years = 5
                mosca_x = 15
                mosca_y = 3
                mosca_z = 6
                hndl_scenario = (
                    "MAGAS KOCKÁZATÚ FORGATÓKÖNYV: A szerver klasszikus kriptográfiát használ (RSA/ECDSA), "
                    "amely jelenleg biztonságos, de nem kvantumálló. Egy fejlett támadó (állami hírszerzés, APT csoport) "
                    "a titkosított forgalmat nagy mennyiségben rögzítheti ('harvest'), majd a CRQC megjelenésekor "
                    "(~2029-2033) Shor-algoritmussal visszafejtheti az összes rögzített TLS munkamenetet. "
                    "A pénzügyi, egészségügyi és személyes adatoknak jellemzően 10-25 éves megőrzési kötelezettsége van, "
                    "ami messze túlnyúlik a CRQC megjelenésén."
                )
                affected_data_types = [
                    "Banki tranzakciók és fizetési adatok",
                    "Ügyfélazonosító adatok (PII)",
                    "API hitelesítő tokenek és munkamenetkulcsok",
                    "Vállalati belső kommunikáció",
                    "Szerződéses és jogi dokumentumok"
                ]
                estimated_financial_impact = (
                    "Magas – becsült kár: €1M - €20M (DORA szabályozói bírság, adatszivárgás miatti "
                    "GDPR bírság, ügyfélbizalom csökkenése, jogi költségek)."
                )
            else:
                risk_level = "MEDIUM"
                exposure_score = 65
                status_text = "KÖZEPES KOCKÁZAT: Nem szabványos konfiguráció, azonnali felülvizsgálat javasolt."
                shelf_life_safe_years = 7
                mosca_x = 10
                mosca_y = 3
                mosca_z = 6
                hndl_scenario = (
                    "KÖZEPES KOCKÁZATÚ FORGATÓKÖNYV: A szerver nem szabványos kriptográfiai konfigurációt használ. "
                    "Az HNDL kitettség mértéke nem állapítható meg pontosan, de a PQC migráció hiánya miatt "
                    "a kvantumkockázat fennáll. Azonnali felülvizsgálat szükséges."
                )
                affected_data_types = [
                    "Általános hálózati forgalom",
                    "Alkalmazás szintű adatok",
                    "Munkamenet tokenek"
                ]
                estimated_financial_impact = (
                    "Közepes – becsült kár: €500K - €5M (szabályozói figyelmeztetés, "
                    "audit hiányosságok, remediációs költségek)."
                )

        # Mosca-egyenlőtlenség kiértékelése
        mosca_sum = mosca_x + mosca_y
        mosca_inequality_holds = mosca_sum > mosca_z
        if mosca_inequality_holds:
            mosca_inequality = f"X({mosca_x}) + Y({mosca_y}) = {mosca_sum} > Z({mosca_z}) → KITETTSÉG FENNÁLL"
        else:
            mosca_inequality = f"X({mosca_x}) + Y({mosca_y}) = {mosca_sum} ≤ Z({mosca_z}) → NINCS AZONNALI KITETTSÉG"

        return {
            "risk_level": risk_level,
            "exposure_score": exposure_score,
            "status_text": status_text,
            "shelf_life_safe_years": shelf_life_safe_years,
            "estimated_crqc_threat_window": "2029 - 2033 (NIST / NSA becslés)",
            "action_required": "ML-KEM-768 hibrid kulcscsere engedélyezése az API átjárón." if not pqc_supported else "Megfelelő védelem fenntartása.",
            "mosca_x": mosca_x,
            "mosca_y": mosca_y,
            "mosca_z": mosca_z,
            "mosca_inequality": mosca_inequality,
            "hndl_scenario": hndl_scenario,
            "affected_data_types": affected_data_types,
            "estimated_financial_impact": estimated_financial_impact
        }
