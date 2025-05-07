#!/usr/bin/env python

import os
import json
import requests
import re
from datetime import datetime
from pathlib import Path
import subprocess
import fcntl

# Constants
Curr_Path = os.path.dirname(os.path.abspath(__file__)) + "/"
Storage_Path = Curr_Path + "StorageFiles/"

CHUNK_SIZE = 2048
TIMEOUT_SECONDS = 20
JSON_DB_PATH = Storage_Path + "cve_db.json"
FIRST_10_CVES_PATH = Storage_Path + "first_10_cves.json"
FAILED_LOG_PATH = Storage_Path + "failed_log.txt"
RUNS_LOG_PATH = Storage_Path + "runs.txt"
NOT_NEEDED_CVES_PATH = Storage_Path + "Not_Needed_CVEs.txt"


def load_json_db():
    if os.path.exists(JSON_DB_PATH):
        with open(JSON_DB_PATH, "r") as file:
            fcntl.flock(file, fcntl.LOCK_SH)
            data = json.load(file)
            fcntl.flock(file, fcntl.LOCK_UN)
            return data
    return {}

def save_json_db(data):
    with open(JSON_DB_PATH, "w") as file:
        fcntl.flock(file, fcntl.LOCK_EX)
        json.dump(data, file, indent=4)
        fcntl.flock(file, fcntl.LOCK_UN)

def load_first_10_cves():
    if os.path.exists(FIRST_10_CVES_PATH):
        with open(FIRST_10_CVES_PATH, "r") as file:
            return json.load(file)
    return []

def save_first_10_cves(data):
    with open(FIRST_10_CVES_PATH, "w") as file:
        json.dump(data, file, indent=4)

def load_failed_log():
    if os.path.exists(FAILED_LOG_PATH):
        with open(FAILED_LOG_PATH, "r") as file:
            return file.read().splitlines()
    return []

def log_failed_download(url, reason):
    with open(FAILED_LOG_PATH, "a") as file:
        file.write(f"{url} - {reason}\n")

def load_not_needed_cves():
    if os.path.exists(NOT_NEEDED_CVES_PATH):
        with open(NOT_NEEDED_CVES_PATH, "r") as file:
            return set(file.read().splitlines())
    return set()

# New one, uses my own projects
def download_cves():
    with open(Curr_Path+"SubProject/README.md", "r") as file:
        lines = file.readlines()[:50] 
    return lines[4:] 

def parse_cve_line(line):
    if not line.strip():
        return None
    
    link_match = re.search(r'\((https://github.com/[\w.-]+/[\w.-]+)\)', line)
    time_match = re.search(r'create time: (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)', line)
    cve_match = re.search(r'(?i)cve-\d{4}-\d+', line)
    
    if link_match and time_match and cve_match:
        url = link_match.group(1).strip() + ".git"
        create_time = time_match.group(1)
        cve_name = cve_match.group(0)
        return url, create_time, cve_name
    return None

def create_directory_structure(cve_name, index):
    today = datetime.today()
    year_folder = Path(Curr_Path) / str(today.year)
    month_folder = year_folder / f"{today.month:02}"
    day_folder = month_folder / f"{today.day:02}"
    cve_folder = day_folder / cve_name / str(index)
    
    while cve_folder.exists():
        index += 1
        cve_folder = day_folder / cve_name / str(index)
    
    cve_folder.mkdir(parents=True)
    
    return cve_folder, index

def create_cve_url_file(download_folder, url):
    file_path = download_folder / "This_Is_The_CVE_URL"
    with open(file_path, "w") as file:
        file.write(url)

def log_new_downloads(new_downloads):
    print("Newly downloaded repositories:")
    for download in new_downloads:
        print(download)

def clone_repo(url, download_folder):
    try:
        result = subprocess.run(
            ["git", "clone", url, str(download_folder)],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"Timeout reached for {url}, skipping...")
        log_failed_download(url, "Timeout")
        return False

def log_run_summary(downloaded_count, failed_count):
    run_date = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    summary = f"Run date: {run_date}\nDownloaded CVEs: {downloaded_count}\nFailed CVEs: {failed_count}\n\n"
    with open(RUNS_LOG_PATH, "a") as file:
        file.write(summary)

def main():
    json_db = load_json_db()
    first_10_cves = load_first_10_cves()
    not_needed_cves = load_not_needed_cves()
    cve_lines = download_cves()
    new_downloads = []
    failed_count = 0

    print("Starting CVE processing...")

    first_10_from_run = []

    for line in cve_lines:
        parsed_data = parse_cve_line(line)
        if parsed_data:
            url, create_time, cve_name = parsed_data
            url_with_date = f"{url}_{create_time}"

            # Skip if CVE is before 2022
            cve_year = int(cve_name.split('-')[1])
            if cve_year < 2022:
                print(f"Skipping {cve_name} as it is before 2022")
                continue

            # Skip if CVE is in Not_Needed_CVEs list
            if cve_name in not_needed_cves:
                print(f"Skipping {cve_name} as it is in Not_Needed_CVEs list")
                continue

            if any(f"{entry['url']}_{entry['create_time']}" == url_with_date for entry in first_10_cves):
                print(f"Existing as {url_with_date} was already downloaded")
                break
            
            # Calculate index and create directory structure
            index = sum(1 for cve in json_db if json_db[cve]["cve_name"] == cve_name) + 1
            download_folder, index = create_directory_structure(cve_name, index)
            
            if not download_folder.exists() or not any(download_folder.iterdir()):
                print(f"Cloning repository: {url} into {download_folder}")
                if clone_repo(url, download_folder):
                    create_cve_url_file(download_folder, url)
                    json_db[url_with_date] = {
                        "create_time": create_time,
                        "cve_name": cve_name,
                        "download_date": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                    }
                    new_downloads.append(url)
                    if len(first_10_from_run) < 10:
                        first_10_from_run.append({
                            "url": url,
                            "create_time": create_time
                        })
                else:
                    failed_count += 1
    
    save_json_db(json_db)

    if len(first_10_from_run) < 10:
        first_10_from_run.extend(first_10_cves)
        first_10_cves = first_10_from_run[:10]
    else:
        first_10_cves = first_10_from_run

    save_first_10_cves(first_10_cves)
    log_new_downloads(new_downloads)
    log_run_summary(len(new_downloads), failed_count)
    print("CVE processing completed.")

if __name__ == "__main__":
    main()
