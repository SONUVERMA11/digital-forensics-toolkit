# ⚡ Pro Digital Forensics Toolkit v3.0

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![CustomTkinter](https://img.shields.io/badge/UI-CustomTkinter-blue?style=for-the-badge)

A powerful, modern **Digital Forensics Workstation** built with Python and CustomTkinter. Designed for forensic analysts, cybersecurity students, and incident responders — featuring a premium dark-themed UI with 11 integrated modules for real-time system analysis, file investigation, and anomaly detection.
<img width="1275" height="802" alt="image" src="https://github.com/user-attachments/assets/9e72b85a-afe4-4fc1-9157-d8a9f70470ae" />

---

## ✨ Features

### 🖥️ Premium Dark UI
- Sleek sidebar navigation with emoji icons
- Live status bar with real-time clock
- Styled cards with rounded corners and gradient accents
- **Segoe UI** + **Cascadia Code** typography

### 📊 11 Forensic Modules

| # | Module | Description |
|---|--------|-------------|
| 1 | **📊 Dashboard** | Live CPU, RAM, Disk gauges · System info · Top processes · Auto-refresh |
| 2 | **🗂️ File Carving** | Recover embedded files (JPEG, PNG, PDF, ZIP, GIF, BMP, MP3, AVI) from raw images |
| 3 | **🏷️ Metadata Extraction** | File properties, EXIF data, MD5/SHA-1/SHA-256 hashes, NTFS timestamps |
| 4 | **🔐 Hash Calculator** | Compute & verify file hashes with progress bar and clipboard copy |
| 5 | **🔍 Hex Viewer** | Raw hex + ASCII view with page navigation and hex pattern search |
| 6 | **💾 USB Analysis** | Detect physical drives & logical partitions via WMI · JSON export |
| 7 | **🧠 Memory Forensics** | Live process analysis with sort, filter, and resource highlighting |
| 8 | **🌐 Network Monitor** | Live connections, per-process breakdown, IO stats · CSV export |
| 9 | **📅 Timeline Reconstruction** | Reconstruct file activity (MOD/ACC/CRE) from any directory · CSV export |
| 10 | **🛡️ Anti-Forensics Detection** | Extension mismatch, hidden files, timestamp anomalies, entropy analysis |
| 11 | **📝 String Extractor** | Extract printable ASCII strings from binaries with offset mapping |

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.10+** (tested on Python 3.14)
- **Windows 10/11** (uses WMI for hardware detection)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/digital-forensics-toolkit.git
   cd digital-forensics-toolkit
   ```

2. **Install dependencies**
   ```bash
   pip install customtkinter psutil Pillow exifread wmi filetype
   ```

3. **Run the toolkit**
   ```bash
   python kit.py
   ```

### Standalone EXE

A pre-built standalone executable (`DF_Toolkit_v3.exe`) is included — no Python installation required. Just double-click to launch.

To build the EXE yourself:
```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name "DF_Toolkit_v3" --collect-all customtkinter kit.py
```

---

## 📦 Dependencies

| Package | Purpose |
|---------|---------|
| `customtkinter` | Modern dark-themed UI framework |
| `psutil` | Process, CPU, memory, network monitoring |
| `Pillow` | Image processing support |
| `exifread` | EXIF metadata extraction from images |
| `wmi` | Windows hardware/device enumeration |
| `filetype` | File type detection by magic bytes |

---

## 🗂️ Project Structure

```
digital-forensics-toolkit/
├── kit.py                 # Main application (all modules)
├── DF_Toolkit_v3.exe      # Standalone executable
└── README.md              # This file
```

---

## 🛠️ Tech Stack

- **Language:** Python 3
- **GUI Framework:** CustomTkinter (dark mode)
- **System APIs:** psutil, WMI, os, hashlib, socket
- **Packaging:** PyInstaller

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) for the beautiful UI framework
- [psutil](https://github.com/giampaolo/psutil) for cross-platform system monitoring
- Python open-source community

---

<p align="center">
  Made with ❤️ by <strong>Sonu Verma</strong>
</p>

