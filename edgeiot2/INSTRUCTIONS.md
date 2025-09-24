# Project Setup and Installation Guide

This document provides step-by-step instructions to set up and run the Network Intrusion Detection System project on a Windows machine.

## 1. Initial Project Setup

These steps are required to run the base application.

### Prerequisites

*   **Python 3:** Ensure you have Python 3.8 or newer installed. You can download it from the [official Python website](https://www.python.org/downloads/). During installation, make sure to check the box that says **"Add Python to PATH"**.
*   **Git:** (Optional) For cloning the project repository.

### Installation

1.  **Clone or Download the Project:**
    *   If you have Git, open a command prompt and run:
        ```bash
        git clone <repository-url>
        cd <project-directory>
        ```
    *   Otherwise, download the project files as a ZIP and extract them.

2.  **Create a Virtual Environment:**
    It is highly recommended to use a virtual environment to manage project dependencies.
    ```bash
    python -m venv venv
    ```

3.  **Activate the Virtual Environment:**
    ```bash
    .\venv\Scripts\activate
    ```
    Your command prompt should now show `(venv)` at the beginning of the line.

4.  **Install Required Python Packages:**
    Run the following command to install all necessary libraries:
    ```bash
    pip install tensorflow scikit-learn imbalanced-learn pandas numpy PyQt5 pyqtgraph joblib
    ```

### Running the Application

Once the installation is complete, you can run the main application:
```bash
python app.py
```

---

## 2. Upcoming Features: Setup Guide

This section will be updated with instructions for new features as they are implemented.

### 2.1. Live Network Packet Capture (Scapy and Npcap)

This feature allows the IDS to analyze real-time traffic from your network.

1.  **Install Scapy:**
    This Python library is used for packet manipulation and capture.
    ```bash
    pip install scapy
    ```

2.  **Install Npcap:**
    Scapy requires a packet capture driver on Windows. Npcap is the modern standard.
    *   Go to the [Npcap download page](https://npcap.com/#download).
    *   Download the latest version of the Npcap installer.
    *   Run the installer and, during installation, make sure to check the box for **"Install Npcap in WinPcap API-compatible Mode"**. This is crucial for compatibility with many Python libraries.

### 2.2. Real Packet Rerouting (Requires Administrator Privileges)

This feature allows the application to block malicious IP addresses by modifying the Windows routing table.

**To use this feature, you must run the application with Administrator rights.**

1.  **Open Command Prompt as Administrator:**
    *   Search for "cmd" or "Command Prompt" in the Start Menu.
    *   Right-click on it and select **"Run as administrator"**.

2.  **Navigate to the Project Directory and Run:**
    In the administrator command prompt, navigate to your project folder and run the application as usual.
    ```bash
    cd path\to\your\project
    .\venv\Scripts\activate
    python app.py
    ```
    The application will now have the necessary permissions to add and remove routes.