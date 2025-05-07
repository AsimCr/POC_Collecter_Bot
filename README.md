# POC_Collecter_Bot

A powerful automated system for discovering, storing, and distributing CVE Proof-of-Concept (POC) exploits | fully integrated with a Telegram bot for user interaction and real-time alerts.

## Components

### 1. CVE POC Collector
Fetches POCs for CVEs from GitHub and other online sources. These are downloaded and stored locally for analysis and reuse.

### 2. POC Database
A local database that:
- Stores POCs by CVE ID.
- Maintains conditions like maximum number of POCs per CVE (e.g. 10), file size limits, and date filtering.
- Preserves POCs even if the source is deleted | ensuring long-term access.

### 3. Telegram Bot (Most Important Component)
A full-featured interface for users to interact with the POC database:

- Search for CVEs and retrieve multiple associated POCs.
- Add CVEs to a personal watchlist and receive alerts when new POCs appear.
- Remove CVEs from the watchlist.
- Subscribe to a newsletter that alerts on the **first occurrence** of any new CVE POC, with a simple description and repository link.

## Setup & Usage

### Requirements
- Python 3.8 or higher
- A Telegram Bot API key

### Installation

1. Clone the repository:
  ```
  git clone https://github.com/AsimCr/POC_Collecter_Bot.git
  cd POC_Collecter_Bot
  ```
2. Replace all API key placeholders in the Python files with your actual Telegram Bot API key.
3. Run the setup script:
  ```
  python Setup.py
  ```
This script will:
- Add cron jobs to:
  - Start the Telegram bot server on boot
  - Run the newsletter scanner periodically
  - Fetch new POCs automatically

## Disclaimer

This tool is intended for **educational and research purposes only**. Do not use it on systems you do not own or have explicit permission to test.

## Contact

For contributions, bug reports, or suggestions, feel free to open an issue or submit a pull request.
