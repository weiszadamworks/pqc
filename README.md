# QuantumShield CBOM & Compliance Engine 🛡️⚛️

> **Enterprise Cryptography Bill of Materials (CBOM) & DORA / NIS2 / PQC Audit Platform**  
> Automatizált külső/belső kriptográfiai leltárkészítés, poszt-kvantum (PQC) kitettség-vizsgálat és vezetői szintű megfelelőségi riportozás bankok, fintech cégek és kritikus infrastruktúrák számára.

---

## 🚀 Főbb Képességek

1. **Szabványos CBOM Leltár (CycloneDX 1.6 Cryptography BOM)**
   - Teljes kriptográfiai eszközleltár előállítása a legfrissebb nemzetközi szabvány szerint (`type: cryptographic-asset`).
   - Protokollok (TLS 1.2, TLS 1.3), cipher suite-ok, aszimmetrikus kulcsok, digitális aláírások és X.509 tanúsítványok automatikus feltérképezése.

2. **Poszt-Kvantum (PQC) Hibrid Kézfogás Szonda**
   - Valós hálózati vizsgálat az IETF és NIST FIPS 203 szabványos **`X25519MLKEM768`** (és Kyber) hibrid kulcscserék támogatottságára.
   - **Harvest Now, Decrypt Later (HNDL)** kockázatelemzés és Mosca-tétele szerinti kitettségi időablak meghatározása.

3. **DORA & NIS2 Felügyeleti Megfelelőségi Index (0-100%)**
   - **DORA 9. Cikk (Kriptográfia és titkosítás)** felügyeleti ellenőrzőpontok és EBA/EIOPA/ESMA technikai szabályzat (RTS) lefedettség.
   - **NIS2 21. Cikk** kiberbiztonsági és titkosítási házirendek kiértékelése.
   - Szigorú felügyeleti pontszámítás (A+, A, B, C, F minősítés).

4. **1-Kattintásos C-Level Executive PDF Riport**
   - Professzionális, nyomtatóbarát PDF audit jelentés a CISO, vezérigazgató és felügyeleti auditorok (pl. MNB, ENISA, Big4) részére.
   - Hivatalos digitális ellenőrző hash-sel és konkrét fejlesztői akciótervvel (Remediation Roadmap).

5. **Kettős Kezelőfelület:**
   - **Modern Web Dashboard:** Letisztult, reaktív felület azonnali vizuális eredményekkel.
   - **Auditor CLI:** Parancssorból vagy CI/CD pipeline-ból automatizálható szkennelés.

---

## 📦 Gyors Indítás (Quick Start)

### 1. Futtatás helyi Python környezetben
```bash
# Függőségek telepítése
pip install -r requirements.txt

# Webes felület és REST API indítása
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Nyisd meg a böngészőben: **`http://localhost:8000`**

### 2. Parancssoros (CLI) Audit Futtatása
```bash
# Egyetlen domain vizsgálata és CBOM + PDF azonnali mentése
python -m app.cli scan cloudflare.com

# Csak a CycloneDX 1.6 CBOM JSON kimenet kérése
python -m app.cli scan api.bank.hu --json-only
```

### 3. Futtatás Dockerrel (Egyetlen paranccsal)
```bash
docker compose up --build
```

---

## 🏛️ Rendszerarchitektúra

```
├── app/
│   ├── main.py                    # FastAPI belépési pont és REST API
│   ├── cli.py                     # Parancssoros auditor futtató (CLI)
│   ├── core/                      # Konfiguráció és PQC/DORA konstansok
│   ├── scanner/                   # TLS szkenner, Tanúsítvány elemző, PQC hibrid szonda
│   ├── engine/                    # CycloneDX 1.6 CBOM motor, DORA pontozó, HNDL kalkulátor
│   ├── reporting/                 # C-Level PDF riport generátor (ReportLab)
│   └── web/                       # Modern Tailwind CSS Web Dashboard
└── tests/                         # Teljes tesztcsomag (SSRF, séma, pontozó, PDF)
```

---

## 💼 Ügyfélszerzési és Értékesítési Útmutató (B2B Sales)

1. **Ingyenes külső audit (Trójai Faló megkeresés):**  
   Futtasd le a publikus API domainre a vizsgálatot (pl. `python -m app.cli scan targetbank.hu`). A generált PDF jelentést küldd el a kiszemelt CISO / Biztonsági Vezető részére:
   > *"Tisztelt CISO! A DORA kötelező kriptográfiai leltár (CBOM) előírása alapján elkészítettük a publikus API végpontjuk gyorsfelmérését. Mellékelten küldjük az audit összefoglalót és a feltárt kvantum-kitettségi kockázatokat."*

2. **Konzulensi & Tanácsadói Partnerség (Big 4 & Audit cégek):**  
   Ajánld fel a motort a DORA/NIS2 auditot végző tanácsadó cégeknek white-label módon, amivel manuális Excel munkát spórolnak meg az ügyfeleiknél.
