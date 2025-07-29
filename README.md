# Virustotal-IOC-Not-detected-by-Crowdstrike
# CrowdStrike Falcon VirusTotal Hash Not-Detected Extractor

## Overview

This **Python script** automates searching VirusTotal Intelligence for files from a given date, then **exports SHA-256 hashes for which CrowdStrike Falcon does NOT detect** any malicious or suspicious activity (or has not scanned at all). The results are outputted to a CSV file and are periodically dumped to avoid data loss if interrupted.

## Features

- Uses the official [`vt-py`](https://pypi.org/project/vt-py/) library to interact with [VirusTotal API v3](https://virustotal.github.io/vt-py/) efficiently.
- Handles API rate limits automatically.
- Periodic results dump to CSV for reliability.
- Filters results for hashes *not detected* by CrowdStrike Falcon.
- Customizable search/query, batch size, and output volume.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [How It Works](#how-it-works)
- [Customizing](#customizing)
- [Dependencies](#dependencies)
- [Caveats & Notes](#caveats--notes)
- [License](#license)

## Quick Start

1. **Install dependencies:**

    ```sh
    pip install vt-py
    ```

2. **Obtain a VirusTotal API key:**  
   Register at [VirusTotal Community](https://www.virustotal.com/gui/join-us) and retrieve your API key from your profile settings.

3. **Save your script:**  
   Save the provided script as `vt_cs.py`.

4. **Edit API key:**  
   Replace `` in the script with your actual API key:
   ```python
   API_KEY = ""
   ```

5. **Run the script:**

    ```sh
    python vt_cs.py
    ```

   Results will be written to `not_detected_by_crowdstrike.csv`.

## Configuration

- `API_KEY`: VirusTotal API Key (required).
- `MAX_RESULTS`: Set the total number of results to process (default: 500).
- `BATCH_SIZE`: Number of API calls per minute (VirusTotal Public API = 4).
- `DUMP_INTERVAL`: How often (in seconds) results are written to the CSV (default: 300 = 5 minutes).
- `OUTPUT_CSV`: Filename for output results.

You can adjust these settings at the top of the script.

## How It Works

1. **Connects to VirusTotal using your API key via the `vt` library**.
2. **Runs an Intelligence search** (query string adjustable, default is files indexed since 2024-07-09).
3. For each result:
    - Retrieves the file's last analysis results.
    - Finds the CrowdStrike Falcon engine's verdict.
    - **Appends to the results only if Falcon shows "not detected" or has not scanned** (verdict not in: `malicious`, `suspicious`, `phishing`, `malware`, `grayware`, `ransomware`).
4. Periodically writes collected hashes to a CSV.
5. Script respects public API's rate limits and stops after processing the desired number of files.

## Example Output

The output CSV will look like:

| Hash                                |
|--------------------------------------|
| 427db86a72c...e97dbf1d0e58f3c894    |
| 2f151acd59b...3f81e2b3e5f13ab8      |
| ...                                 |

Only hashes NOT flagged by CrowdStrike Falcon are included.

## Customizing

- **Query:**  
  The search query (`"fs:2024-07-09+"`) can be changed to match your use case. See [VirusTotal Query Syntax](https://docs.virustotal.com/reference/search) for details.

- **Detection categories:**  
  The set in `DETECTION_CATEGORIES` can be customized to filter on other verdicts.

- **Batch size and output size** can be tuned to fit your API quota and needs.

## Dependencies

- Python 3.7+
- [`vt-py`](https://pypi.org/project/vt-py/) (official VirusTotal client, install with `pip install vt-py`).

## Caveats & Notes

- **Only hashes missing CrowdStrike Falcon detection are exported.**
- Heavy use may hit API rate limits—defaults should be safe for free/public tier.
- **Keep your API key secret.**
- The script was tested with Python 3.7+ and the VirusTotal Public API. For higher quotas, use an Enterprise API key.

## License

Licensed under the Apache 2.0 License.
