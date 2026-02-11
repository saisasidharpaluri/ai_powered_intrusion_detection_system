# AI-Powered Network Intrusion Detection System (NIDS)

An **AI-driven Network Intrusion Detection System** capable of capturing live network traffic and classifying it as "Normal" or "Malicious" in real-time. This project leverages **Machine Learning (Random Forest)**, **Scapy** for packet sniffing, and **Flask** for web-based visualization.

<img width="915" height="491" alt="image" src="https://github.com/user-attachments/assets/ffcb6ffe-04c3-4083-8b21-f5aedb42fec8" />


## 🚀 Features

- **Packet Sniffing**: Captures live TCP/UDP/ICMP packets using `Scapy`.
- **Real-Time Feature Extraction**: Extracts key attributes (Protocol, Service, Flags, Payload Size) from raw packets on the fly.
- **ML-Based Detection**: Uses a **Random Forest Classifier** trained on the **NSL-KDD** dataset to identify anomalies.
- **Live Dashboard**: A responsive **Flask** web interface that updates instantaneously with colored alerts (Green = Safe, Red = Malicious).
- **Logging**: Automatically logs all detected traffic to `alerts.json` for persistent record-keeping.

## 🛠️ Tech Stack

- **Language**: Python 3.x
- **Machine Learning**: Scikit-Learn (Random Forest), Pandas, NumPy
- **Networking**: Scapy
- **Web Framework**: Flask, Jinja2, HTML/CSS
- **Dataset**: NSL-KDD

## ⚙️ Installation

1.  **Clone the repository**

    ```bash
    git clone https://github.com/saisasidharpaluri/ai_powered_intrusion_detection_system.git
    cd ai_powered_intrusion_detection_system
    ```

2.  **Set up Virtual Environment**

    ```bash
    python -m venv venv
    # Windows
    .\venv\Scripts\activate
    # Mac/Linux
    source venv/bin/activate
    ```

3.  **Install Dependencies**
    Note: On Windows, you must have [Npcap](https://npcap.com/) installed (usually comes with Wireshark).
    ```bash
    pip install -r requirements.txt
    ```

## 🏃 Usage

### 1. Train the Model

This step generates the `.pkl` model files (`rf_model.pkl`, encoders, etc.).

```bash
python train_model.py
```

### 2. Start the Dashboard

Open a terminal and run the Flask server.

```bash
python app.py
```

Access the dashboard at: `http://127.0.0.1:5000`

### 3. Start the Packet Sniffer

Open **another terminal** (Run as Administrator/root if needed for packet capture) and run:

```bash
python sniffer.py
```

The sniffer will begin capturing traffic and sending alerts to the dashboard.

## 📊 Dataset

This project uses the **NSL-KDD** dataset, a refined version of the original KDD'99 dataset, widely used for benchmarking intrusion detection systems.
