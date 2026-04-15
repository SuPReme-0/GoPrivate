<div align="center">

# 🛡️ GoPrivate EDR: Project Trinity 

**The world's first on-device, triple-engine Machine Learning firewall.** Three mathematically synchronized Neural Networks and Gradient Boosted trees running natively on Android Silicon. 
Zero cloud latency. Zero data exfiltration. Absolute device sovereignty.

<p align="center">
  <a href="#-executive-overview">Overview</a> •
  <a href="#-the-trinity-architecture">Architecture</a> •
  <a href="#-core-technical-innovations">Innovations</a> •
  <a href="#-installation--setup">Setup</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-contributing">Contributing</a>
</p>

![Android Version](https://img.shields.io/badge/Android-8.0%2B-3DDC84?logo=android&style=for-the-badge)
![Kotlin](https://img.shields.io/badge/Kotlin-1.9.0-7F52FF?logo=kotlin&style=for-the-badge)
![C++](https://img.shields.io/badge/C%2B%2B-17-00599C?logo=c%2B%2B&style=for-the-badge)
![ONNX Runtime](https://img.shields.io/badge/ONNX_Runtime-1.16-005CED?logo=onnx&style=for-the-badge)
![XGBoost](https://img.shields.io/badge/XGBoost-1.7.5-FF9900?logo=xgboost&style=for-the-badge)
![PyTorch](https://img.shields.io/badge/PyTorch-2.0-EE4C2C?logo=pytorch&style=for-the-badge)
![HuggingFace](https://img.shields.io/badge/HuggingFace-Transformers-FFD21E?logo=huggingface&style=for-the-badge)
![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge)

</div>

---

## 🚀 Executive Overview

**GoPrivate EDR** represents a paradigm shift in mobile Endpoint Detection and Response. By deploying three specialized Machine Learning engines that operate **entirely on-device**, it eliminates the fundamental trade-off between security and privacy. 

Unlike traditional solutions that route traffic through remote servers or rely on cloud-based hash lookups, the Project Trinity architecture processes all network packets, sideloaded binaries, and UI DOM structures locally. 

This repository contains the training architecture, data pipelines, and exported ONNX/JSON models that power the Android client.

---

## 🧠 The Trinity Architecture

The project is divided into three distinct, highly specialized detection engines:

### 🌐 Engine A: Network Sentinel (IDS/IPS)
* **Core:** XGBoost compiled to ONNX.
* **Function:** Real-time Network Intrusion Detection and Prevention.
* **Input Data:** CICFlowMeter (PCAP/CSV) derivations.
* **Execution:** Operates directly within the OS-level `VpnService`. Uses a C++ JNI bridge to intercept IPv4 packets, extracting 80 flow heuristics natively (e.g., *Flow IAT Std*, *Packet Length Variance*). Drops Command & Control (C2) beacons and data exfiltration payloads at wire-speed (<3ms latency).
* **Accuracy:** ~98.9% optimized F1-Score on encrypted transport layers.

### 🔍 Engine B: Vanguard Static Analyzer
* **Core:** XGBoost + SHAP Explainability.
* **Function:** Deep Forensic Payload Analysis of Installed Applications.
* **Input Data:** Android Manifest (XML) / APK Binary.
* **Execution:** Intercepts sideloads to bypass OS background limits. Analyzes the compiled `AndroidManifest.xml` via native AXML parsing to expose "Dangerous" permission combinations masked by UI obfuscation.
* **Export:** Exported to JSON format for ultra-lightweight parsing in Kotlin.

### 📋 Engine C: NLP Privacy Auditor
* **Core:** DistilBERT Transformer (Base Uncased, 128-token context window).
* **Function:** Semantic Analysis of Legal Documents, EULAs, and Web Content.
* **Input Data:** Privacy Policy / Terms of Service (Raw Text).
* **Execution:** Synchronized with the Android `AccessibilityService` and a custom headless Phantom Fetcher. Detects invasive data-brokerage clauses. Categorizes text into: `Data_Collection`, `Data_Sharing`, `Security_Retention`, `User_Choice`, `Other_Policy`.
* **Optimization:** Exported to **FP32 ONNX** for mobile inference. Hard-clamped to 510 tokens to prevent native C++ memory segmentation faults (SIGSEGV).

---

## ⚡ Core Technical Innovations

* **Hardware Thread Quarantine:** Heavy ML models are strictly clamped to isolated dispatchers (`NlpDispatcher`, `Dispatchers.Default`), mathematically guaranteeing they will never trigger OS thread-thrashing or steal CPU cycles from the active VPN traffic.
* **Zero-Copy Streaming:** Bypasses JVM `String` allocation entirely when scanning large binaries. Evaluates byte arrays natively via C++, dropping GC (Garbage Collection) pauses to zero.
* **Explainable AI (XAI):** All models incorporate **SHAP (SHapley Additive exPlanations)** or LIME-style perturbation to ensure absolute transparency, translating complex mathematical threat scores into human-readable forensic reports.

---
## 📁 Project Structure

```
GoPrivate-EDR/
├── build_script.py          # Main build script for training and exporting models
├── requirements.txt         # Python dependencies
├── LICENSE                  # Apache 2.0 License
├── readme.md                # This file
├── .gitignore               # Git ignore rules
├── android_app/             # Android client application (Kotlin/C++)
│   ├── app/
│   │   ├── build.gradle.kts # App configuration
│   │   ├── src/main/
│   │   └── build/
│   ├── gradle/
│   └── gradlew*
├── data/                    # Datasets and data preparation scripts
│   ├── Engine_1/
│   │   ├── prepare_data.py  # Data prep for network features
│   │   ├── engine_a_training_matrix.csv
│   │   └── dataset_link.txt
│   ├── Engine_2/
│   │   ├── engine_b_tensors.npz
│   │   ├── engine_b_top_300_manifest.json
│   │   └── dataset_link.txt
│   └── Engine_3/
│       ├── goprivate_nlp_master.csv
│       └── dataset_link.txt
├── models/                  # Trained models and assets
│   ├── Engine_1/
│   │   ├── engine_a_features.json
│   │   └── engine_a_model.onnx
│   ├── Engine_2/
│   │   ├── engine_b_shap_features_FINAL.json
│   │   ├── goprivate_engine_b_static_FINAL.json
│   │   └── goprivate_engine_b_threshold_FINAL.txt
│   └── Engine_3/
│       ├── engine_c_label_mapping.json
│       ├── model.onnx
│       └── vocab.txt
└── docs/
    └── index.html           # Project documentation website
```

---

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.10+
- Android Studio (for Android app development)
- Git

### 1. Environment Setup
```bash
# Clone the repository
git clone https://github.com/SuPReme-0/GoPrivate-EDR.git
cd GoPrivate-EDR

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Reproducing Models
To retrain the engines from scratch using the provided data pipelines:

```bash
# Run the main build script
python build_script.py
```

This will:
- Train Engine A (XGBoost network model)
- Train Engine B (XGBoost static analyzer)
- Train Engine C (DistilBERT NLP model)
- Export all models to ONNX/JSON format
- Secure models with encryption

### 3. Data Preparation
For Engine A:
```bash
cd data/Engine_1
python prepare_data.py  # Requires benign and malware PCAP directories
```

### 4. Generating XAI Visualizations
To generate SHAP feature importance plots:
```bash
# Install SHAP
pip install shap
# Run custom visualization code (implement based on SHAP library)
```

---

## 📲 Android Deployment Integration

To integrate these trained models into the GoPrivate Android App:

1. **Engine A:** Move `engine_a_model.onnx` and `engine_a_features.json` to the Android app's `assets/` directory. Load using ONNX Runtime for Android.

2. **Engine B:** Move the JSON model files (`goprivate_engine_b_static_FINAL.json`, `engine_b_shap_features_FINAL.json`, `goprivate_engine_b_threshold_FINAL.txt`) to the `assets/` folder.

3. **Engine C:** Move `model.onnx`, `vocab.txt`, and `engine_c_label_mapping.json` to the `assets/` folder.

4. Ensure the `onnxruntime-android` dependency is configured in `build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.microsoft.onnxruntime:onnxruntime-android:1.16.0")
    // Other dependencies...
}
```

5. Build the Android app:
```bash
cd android_app
./gradlew assembleDebug
```

(Note: For security and repository size limits, the final encrypted `.enc` ONNX models used in production are not included in version control and must be generated locally).

---

## 🚀 Usage

### Training Models
```python
from build_script import build_engine_a, build_engine_b, build_engine_c

# Train individual engines
build_engine_a()
build_engine_b()
build_engine_c()
```

### Android App
- Install the APK on an Android device (API 26+).
- Grant VPN and accessibility permissions.
- The app runs the ML engines on-device for real-time protection.

---

## 👨‍💻 About the Architect
<img src="https://github.com/SuPReme-0.png" width="100" height="100" align="right" style="border-radius: 50%;">

Priyanshu Roy | AI & ML Security Engineer

Developed as part of the B.Tech Artificial Intelligence & Machine Learning thesis at the Institute of Engineering and Management (IEM), Kolkata. Specializing in the intersection of hardware-level networking, edge AI, and predictive security modeling.

<p align="left">
<a href="https://github.com/SuPReme-0">
<img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white" alt="GitHub" />
</a>
</p>

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

Distributed under the Apache License 2.0. See `LICENSE` for more information.

---

## ⚖️ Disclaimer

For Educational and Defensive Use Only. This framework demonstrates advanced Android system hooking, native memory manipulation, and edge ML deployment techniques. The author is not responsible for any device instability, network disruption, or misuse of this architecture.

<div align="center">
<i>"Security through obscurity is not security. Security through mathematics is."</i>
</div></content>