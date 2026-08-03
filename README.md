# CERT-BUND-ANALYZER
CERT-Bund analyzer tool for analyzing and visualizing CERT-Bund files.

## Overview
This tool automates the ingestion, deduplication, analysis, and reporting of CERT-Bund CSV intelligence files. It features a Django-based web application and standalone scripts to process network indicators and automatically generate incident response advisories and Word documents using OpenRouter (AI summarization), Team Cymru, PeeringDB, and DuckDuckGo for OSINT enrichment.

## Installation & Setup

### Prerequisites
- Python 3.10+
- `git-crypt` (Required to decrypt the database and historical deduplication data)

### 1. Clone & Decrypt the Repository
Because this repository stores sensitive historical fingerprints (`seen_combos.txt`) and a database (`db.sqlite3`), those files are encrypted using `git-crypt`.

1. Install [`git-crypt`](https://github.com/AGWA/git-crypt/releases) for your operating system.
2. Clone the repository:
   ```bash
   git clone <repository_url>
   cd CERT-BUND-ANALYZER
   ```
3. Securely obtain the decryption key (`seen_combos_secret.key`) from an authorized team member.
4. Decrypt the repository:
   ```bash
   /path/to/git-crypt unlock /path/to/seen_combos_secret.key
   ```
*(After running this command, `seen_combos.txt` and `db.sqlite3` will be transformed into readable plain-text on your local machine).*

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Environment Variables
Create a `.env` file in the root directory. You may need to configure external API keys (e.g., `OPENROUTER_API_KEY`) depending on your usage requirements.

### 4. Running the Web Application
Start the Django development server:
```bash
python cert_bund_analyzer.py
```
*Note: If `seen_combos.txt` is missing, the application will warn you to create it to act as the baseline.*

## Features
- **Intelligent Deduplication**: Strictly tracks seen fingerprints across runs to avoid duplicate alerts.
- **Automated OSINT**: Enhances malware data with DuckDuckGo intelligence and AI.
- **Automatic ASN Lookups**: Falls back through Team Cymru, PeeringDB, and RIPE Stat to resolve Autonomous System organizations.
- **Reporting**: Automatically exports `.docx` advisories ready for dissemination.
