<div align="center">

# 🛡️ GoPrivate EDR: Project Trinity 

**The world's first on-device, triple-engine Machine Learning firewall.** Three mathematically synchronized Neural Networks running natively on Android Silicon. 
Zero cloud latency. Zero data exfiltration. Absolute device sovereignty.

<p align="center">
  <a href="#-executive-overview">Overview</a> •
  <a href="#-the-trinity-architecture">Architecture</a> •
  <a href="#-core-technical-innovations">Innovations</a> •
  <a href="#-installation--setup">Setup</a>
</p>

![Android Version](https://img.shields.io/badge/Android-11%2B-3DDC84?logo=android&style=for-the-badge)
![Kotlin](https://img.shields.io/badge/Kotlin-1.9.0-7F52FF?logo=kotlin&style=for-the-badge)
![C++](https://img.shields.io/badge/C%2B%2B-17-00599C?logo=c%2B%2B&style=for-the-badge)
![ONNX Runtime](https://img.shields.io/badge/ONNX_Runtime-1.16-005CED?logo=onnx&style=for-the-badge)
![XGBoost](https://img.shields.io/badge/XGBoost-1.7.5-FF9900?logo=xgboost&style=for-the-badge)
![HuggingFace](https://img.shields.io/badge/HuggingFace-Transformers-FFD21E?logo=huggingface&style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

</div>

---

## 🚀 Executive Overview

**GoPrivate EDR** represents a paradigm shift in mobile Endpoint Detection and Response. By deploying three specialized Machine Learning engines that operate **entirely on-device**, it eliminates the fundamental trade-off between security and privacy. 

Unlike traditional solutions that route traffic through remote servers or rely on cloud-based hash lookups, the Project Trinity architecture processes all network packets, sideloaded binaries, and UI DOM structures locally. 

This repository contains the training architecture, data pipelines, and exported ONNX/JSON models that power the Android client.

---

## 🧠 The Trinity Architecture

The project is divided into three distinct, specialized detection engines:

### 🌐 Engine A: Network Sentinel (IDS/IPS)
* **Core:** XGBoost compiled to ONNX.
* **Function:** Real-time Network Intrusion Detection and Prevention.
* **Input Data:** CICFlowMeter (PCAP/CSV).
* **Execution:** Operates directly within the OS-level `VpnService`. Uses a C++ JNI bridge to intercept IPv4 packets, extracting 45 flow heuristics natively (e.g., *Flow IAT Std*, *Packet Length Variance*). Drops Command & Control (C2) beacons and data exfiltration payloads at wire-speed (<5ms latency).
* **Accuracy:** ~95.4% on the Android_Malware dataset.

### 🔍 Engine B: Vanguard Static Analyzer
* **Core:** XGBoost + SHAP Explainability.
* **Function:** Deep Forensic Payload Analysis of Installed Applications.
* **Input Data:** Android Manifest (XML) / APK Binary.
* **Execution:** Intercepts sideloads via a 1ms handoff protocol to bypass Android 14 background limits. Analyzes the `AndroidManifest.xml` for "Dangerous" permission combinations (e.g., `SEND_SMS`, `RECEIVE_BOOT_COMPLETED`).
* **Export:** Exported to JSON format for ultra-lightweight parsing in Kotlin.

### 📋 Engine C: NLP Privacy Auditor
* **Core:** DistilBERT Transformer (Base Uncached, 128-token context).
* **Function:** Semantic Analysis of Legal Documents, EULAs, and Web Content.
* **Input Data:** Privacy Policy / Terms of Service (Text).
* **Execution:** Synchronized with the Android `AccessibilityService`. Detects invasive data-brokerage clauses. Categorizes text into: `Data_Collection`, `Data_Sharing`, `Security_Retention`, `User_Choice`, `Other_Policy`.
* **Optimization:** Exported to **FP32 ONNX** for mobile inference. Latency is ~50ms per clause on modern Android hardware.

---

## ⚡ Core Technical Innovations

* **Hardware Thread Quarantine:** Heavy ML models are hard-clamped to isolated threads, mathematically guaranteeing they will never trigger OS thread-thrashing or steal CPU cycles from the VPN traffic.
* **Zero-Copy Streaming:** Bypasses JVM `String` allocation entirely when scanning 100MB+ files. Evaluates byte arrays natively, dropping GC (Garbage Collection) pauses to zero.
* **Explainable AI (XAI):** All models incorporate **SHAP (SHapley Additive exPlanations)** to ensure transparency, translating mathematical threat scores into human-readable capabilities.

---

## 📁 Project Structure

```text
GoPrivate-EDR/
├── build/                # Training & ETL Scripts (Run these to reproduce models)
│   ├── Engine_1.py       # XGBoost Network Training Pipeline
│   ├── Engine_2.py       # XGBoost Static Permission Training Pipeline
│   ├── Engine_3.py       # DistilBERT NLP Training Pipeline
│   └── Engine_XAI_Visualizer.py # SHAP Visualization Script
├── data/                 # Raw and Processed Datasets (Engine A, B, C)
├── models/               # Final Production Assets (.json, .onnx, .txt)
│   ├── Engine_1/         # Network Model
│   ├── Engine_2/         # Static Permission Model
│   └── Engine_3/         # DistilBERT NLP ONNX Model
├── android_app/          # The GoPrivate Android Client (Kotlin/C++)
├── docs/                 # Architecture diagrams & UI Portal
├── requirements.txt      # Project-wide Python dependencies
└── .gitignore
🛠️ Installation & Setup
1. Environment Setup
It is recommended to use Python 3.10+ and a virtual environment:

Bash
# Clone the repository
git clone [https://github.com/SuPReme-0/GoPrivate-EDR.git](https://github.com/SuPReme-0/GoPrivate-EDR.git)
cd GoPrivate-EDR

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
2. Reproducing Models
To retrain the engines from scratch using the provided data pipelines:

Bash
cd build

# Train the Network Sentinel
python Engine_1.py

# Train the Vanguard Static Analyzer
python Engine_2.py

# Train the NLP Privacy Auditor (Requires GPU for practical training times)
python Engine_3.py
3. Generating XAI Visualizations
To generate the SHAP feature importance plots (used in Chapter 5 of the thesis):

Bash
python build/Engine_XAI_Visualizer.py
📲 Android Deployment Integration
To integrate these trained models into the GoPrivate Android App:

Engine A & B: * Move the exported .json model files into the Android app's assets/ directory.

Load them using a lightweight XGBoost-to-JSON parser in Kotlin.

Engine C: * Move model.onnx, vocab.txt, and engine_c_label_mapping.json to the assets/ folder.

Ensure the onnxruntime-android dependency is configured in your build.gradle for on-device execution.

(Note: For security and repository size limits, the final encrypted .enc ONNX models used in production are not included in version control and must be generated locally).

👨‍💻 About the Architect
<img src="https://www.google.com/search?q=https://github.com/SuPReme-0.png" width="100" height="100" align="right" style="border-radius: 50%;">

Priyanshu Roy AI & ML Security Engineer

Developed as part of the B.Tech Artificial Intelligence & Machine Learning thesis at the Institute of Engineering and Management (IEM), Kolkata. Specializing in the intersection of hardware-level networking, edge AI, and predictive security modeling.

<p align="left">
<a href="https://github.com/SuPReme-0">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/GitHub-100000%3Fstyle%3Dfor-the-badge%26logo%3Dgithub%26logoColor%3Dwhite" alt="GitHub" />
</a>
</p>

⚖️ Disclaimer & License
For Educational and Defensive Use Only. > This framework demonstrates advanced Android system hooking, native memory manipulation, and edge ML deployment techniques. The author is not responsible for any device instability, network disruption, or misuse of this architecture.

Distributed under the MIT License. See LICENSE for more information.

<div align="center">
<i>“Security through obscurity is not security. Security through mathematics is.”</i>
</div>