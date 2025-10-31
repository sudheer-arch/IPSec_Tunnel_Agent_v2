# IPsec Tunnel AI Agent POC

This project is a proof-of-concept for an AI-powered agent that analyzes the health of IPsec tunnels from a FortiGate firewall. It provides a user-friendly web interface built with Gradio to display the analysis, summarize the tunnel status, and suggest actions.

## Features

*   **Tunnel Health Analysis:** Fetches IPsec tunnel data from a FortiGate firewall.
*   **AI-Powered Summary:** Uses a large language model to generate a human-readable summary of the tunnel status.
*   **Action Proposals:** Suggests actions to be taken based on the analysis.
*   **Web-Based UI:** Provides a simple and interactive web interface for analysis and actions.

## Setup and Usage

1.  **Prerequisites:**
    *   Python 3.x
    *   Access to a FortiGate firewall with the REST API enabled.
    *   Access to a Large Language Model (LLM) with an API endpoint.

2.  **Installation:**
    *   Clone the repository:
        ```bash
        git clone https://github.com/sudheer-arch/IPSec_Tunnel_Agent_v2.git
        cd IPSec_Tunnel_Agent_v2
        ```
    * Create a virtual environment:
        ```bash
        python -m venv .venv
        ```

    * Activate the virtual environment:
        - On Windows:
        ```bash
        .venv\Scripts\activate
        ```
        - On macOS and Linux:
        ```bash
        source .venv/bin/activate
        ```

    *   Install the required Python packages:
        ```bash
        pip install -r requirements.txt
        ```

4.  **Running the Application:**
    *   Execute the `main.py` script:
        ```bash
        python main.py
        ```
    *   Open your web browser and navigate to the URL provided by Gradio (usually `http://127.0.0.1:7860`).

## How It Works

1.  The application fetches IPsec tunnel data from the FortiGate firewall's API.
2.  The data is then sent to a large language model to generate a summary of the tunnel health.
3.  The application also uses the LLM to propose actions based on the status of the tunnels.
4.  The summary and proposed actions are displayed in a Gradio web interface.
5.  The user can approve or deny the proposed actions from the UI.
