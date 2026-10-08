# Forensix: Integrated Secure Data Erasure & Advanced File Recovery Platform

**Smart India Hackathon 2026 (SIH26149)**
* **Organization:** National Technical Research Organisation (NTRO)
* **Category:** Software
* **Theme:** Blockchain & Cybersecurity

---

**To remove the directory from Git's index without deleting your local files:**

```bash

git rm -r --cached reports

```

## 📌 Executive Summary

**Forensix** is a unified digital forensics and cybersecurity platform that integrates **Secure Hardware & Logical Data Sanitization** with **Advanced Forensic File Carving & Recovery**.

Existing tools force cybersecurity teams and law enforcement agencies to use separate, fragmented software for wiping (e.g., DBAN, Blancco) and recovery (e.g., Autopsy, Scalpel, PhotoRec). **Forensix** unifies both capabilities into a single environment built specifically for the **National Technical Research Organisation (NTRO)** under **SIH 2026 (SIH26149)**.

---

## 🎯 Target Audience & Use Cases

* **Law Enforcement & Forensics Units:** Extracting deleted evidence from seized drives, USBs, and memory cards without relying on filesystem metadata.
* **Cybersecurity & IT Defense Teams:** Securely destroying sensitive data on decommissioned hardware to prevent unauthorized recovery.
* **Government & Military Agencies (NTRO):** Guaranteeing media sanitization compliance with court-verifiable audit reports.

---

## 🛠️ Technology Stack

| Component | Technology / Library | Description |
| :--- | :--- | :--- |
| **Language** | Java 17 / 21 | Modern JDK platform for cross-platform execution |
| **Build System** | Apache Maven | Project dependency management & build orchestration |
| **Native OS Access** | JNA (Java Native Access) | Win32 API & POSIX system calls for low-level block IOCTLs |
| **PDF Reporting** | Apache PDFBox 3.0.2 | Cryptographic PDF certificate generator for legal audits |
| **JSON Handling** | Jackson 2.17.0 | Structured device metadata & audit log serialization |
| **Cryptography** | Java `MessageDigest` + `SecureRandom` | SHA-256 evidence hashing & cryptographically secure wiping patterns |

---

## 🏗️ Solution Architecture & Module Structure

```
com.forensix/
├── Main.java                    ← CLI menu orchestrator
├── audit/
│   └── ReportGenerator.java     ← Module 4: PDF certificate generator
├── carver/
│   ├── FileCarver.java          ← Module 3: Raw sector file carving engine
│   └── FileSignature.java       ← Magic-byte signatures (JPEG, PNG, PDF, ZIP)
├── eraser/
│   ├── DriveEraser.java         ← Module 1: Block-level drive sanitization
│   └── FileEraser.java          ← Module 2: Selective file + slack space wiping
├── model/
│   ├── CarvedFile.java          ← Data model for carved evidence
│   ├── SanitizationStandard.java ← Enum: NIST 800-88, DoD 5220.22-M, Gutmann, Zero-fill
│   └── StorageDevice.java       ← Data model for physical/logical drives
├── nativeio/
│   └── StorageDetector.java     ← Cross-platform drive detection (Win32/Linux)
└── util/
    ├── EntropyCalculator.java   ← Shannon entropy (bits/byte) calculator
    └── HashUtil.java            ← SHA-256 hash utility
```

---

## ⚙️ Module-by-Module Technical Breakdown

### Module 1: Secure Drive Eraser (`DriveEraser.java`)
* **Block-Level Wiping:** Overwrites entire physical drives or disk images sequentially across LBAs.
* **Standards Supported:** NIST SP 800-88 Rev 1 (Clear & Purge), DoD 5220.22-M (3-pass), Gutmann Lite (7-pass), Zero-fill, Random-fill.
* **Real-Time Shannon Entropy:** Measures buffer entropy ($0.0$ bits = pure zero fill, $8.0$ bits = random) live during wiping and executes a verification pass to confirm zero residual readable data.
* **System Drive Protection Lock:** Hardcoded protection guards prevent accidental selection/wiping of OS system drives.

### Module 2: Secure File & Slack Space Eraser (`FileEraser.java`)
* **Selective File Deletion:** Multi-pass overwrite of targeted files.
* **Slack Space Scrubbing:** Zeroes out residual leftover bytes in cluster boundaries (e.g., 500-byte file in a 4096-byte cluster leaves 3596 bytes of slack space).
* **Metadata & Timestamp Destruction:** Resets file modification/creation times to Epoch 1970 and scrambles file names prior to deletion to destroy MFT/Inode entry traces.

### Module 3: Advanced File Carving (`FileCarver.java` & `FileSignature.java`)
* **Filesystem-Less Recovery:** Extracts deleted files directly from raw disk sectors by scanning for magic bytes (`JPEG`, `PNG`, `PDF`, `ZIP/DOCX`).
* **Overlapping Sector Buffers:** 4096-byte buffer overlap prevents missing file signatures split across chunk boundaries.
* **Confidence Scoring & Hashing:** Evaluates structural validity (0–100% score) and computes a SHA-256 hash for forensic chain-of-custody.

### Module 4: Cryptographic Audit & Reporting (`ReportGenerator.java`)
* **Court-Ready PDF Certificates:** Exports PDF certificates detailing device model, serial number, sanitization standard used, pass counts, SHA-256 hashes, and entropy verification results.

---

## 🚀 Getting Started & Build Instructions

### Prerequisites
* **Java 17+ / Java 21 JDK**
* **Apache Maven 3.8+**
* Administrator / Root privileges (required for raw block IO device access).

### Compilation & Build
```bash
# Clone repository
git clone https://github.com/PrashantJaybhaye/SIH26149-prototype.git
cd SIH26149-prototype

# Build with Maven
mvn clean compile
```

### Running the Interactive CLI Dashboard
```bash
# Execute Main Application
mvn exec:java -Dexec.mainClass="com.forensix.Main"
```

### Automated Demonstration Mode
Selecting **Option 5** in the main menu executes an end-to-end demonstration:
1. Creates a synthetic 10 MB `.raw` disk image with embedded JPEG and PDF forensic evidence.
2. Carves and extracts evidence files into `carved_evidence/`.
3. Sanitizes the raw disk image using **NIST SP 800-88 Clear (Pass 1)** while measuring entropy.
4. Generates a court-ready PDF Audit Certificate in `reports/`.

---

## 📄 Compliance & Governance
Designed for National Technical Research Organisation (NTRO) - SIH 2026.
Compliant with:
* **NIST SP 800-88 Rev 1** (Guidelines for Media Sanitization)
* **DoD 5220.22-M** (National Industrial Security Program Operating Manual)
* **ISO/IEC 27040** (Storage Security)

