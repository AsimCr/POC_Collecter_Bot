#!/usr/bin/env python

import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path

# Constants
Curr_Path = os.path.dirname(os.path.abspath(__file__)) + "/"
CVE_Archive_Path = Curr_Path + "CVE_Archive/"
CVE_Folder_Path = Curr_Path + str(datetime.now().year) + "/"
Days_Threshold = 30
Max_Subfolders_Per_CVE = 20
Not_Needed_CVEs_Path = Curr_Path + "Not_Needed_CVEs.txt"

def archive_old_cves():
    # Ensure the archive directory exists
    if not os.path.exists(CVE_Archive_Path):
        os.makedirs(CVE_Archive_Path)

    # Calculate the date threshold
    threshold_date = datetime.now() - timedelta(days=Days_Threshold)

    # Go through each CVE folder in the main CVE directory, sorted by date
    cve_folders = sorted(Path(CVE_Folder_Path).glob('*/*/*'), key=extract_date_from_path)
    for cve_folder in cve_folders:
        if cve_folder.is_dir():
            folder_date = extract_date_from_path(cve_folder)
            if folder_date < threshold_date:
                archive_cve_folder(cve_folder)

def extract_date_from_path(path):
    # Extract the date parts from the folder path
    year = int(path.parts[-4])
    month = int(path.parts[-3])
    day = int(path.parts[-2])
    return datetime(year, month, day)

def archive_cve_folder(cve_folder):
    # Extract the CVE name from the folder path
    cve_name = cve_folder.parts[-1]

    # Create the archive path for the CVE if it doesn't exist
    archive_cve_path = Path(CVE_Archive_Path) / cve_name
    if not archive_cve_path.exists():
        archive_cve_path.mkdir(parents=True)

    # Get the list of subfolders and sort them by their names to maintain order
    subfolders = sorted(list(cve_folder.glob('*')), key=lambda x: int(x.name))
    current_subfolders = list(archive_cve_path.glob('*'))
    current_count = len(current_subfolders)

    # Calculate how many subfolders can be moved
    subfolders_to_move = subfolders[:Max_Subfolders_Per_CVE - current_count]

    # Move the subfolders to the archive directory, respecting the max limit
    for subfolder in subfolders_to_move:
        if subfolder.exists():
            target_path = archive_cve_path / subfolder.name
            if target_path.exists():
                target_path = get_unique_path(target_path)
            shutil.move(str(subfolder), target_path)
            current_count += 1

    # Remove any remaining subfolders beyond the limit
    for subfolder in subfolders[Max_Subfolders_Per_CVE - current_count:]:
        if subfolder.exists():
            shutil.rmtree(subfolder)

    # If there are no more subfolders in the original CVE folder, remove it
    if not any(cve_folder.iterdir()):
        cve_folder.rmdir()
        # Remove parent directories if they are empty
        remove_empty_parents(cve_folder)

    # If the archive CVE folder has reached Max_Subfolders_Per_CVE, add to Not_Needed_CVEs.txt
    if current_count >= Max_Subfolders_Per_CVE:
        add_to_not_needed_cves(cve_name)

def get_unique_path(path):
    """Append a counter to the path name if it already exists to avoid collisions."""
    counter = 1
    new_path = Path(f"{path}_{counter}")
    while new_path.exists():
        counter += 1
        new_path = Path(f"{path}_{counter}")
    return new_path

def add_to_not_needed_cves(cve_name):
    if not os.path.exists(Not_Needed_CVEs_Path):
        with open(Not_Needed_CVEs_Path, "w") as file:
            file.write(f"{cve_name}\n")
    else:
        with open(Not_Needed_CVEs_Path, "r") as file:
            existing_cves = file.read().splitlines()
        if cve_name not in existing_cves:
            with open(Not_Needed_CVEs_Path, "a") as file:
                file.write(f"{cve_name}\n")

def remove_empty_parents(path):
    for parent in path.parents:
        try:
            parent.rmdir()
        except OSError:
            break

def main():
    print("Starting CVE archiving process...")
    archive_old_cves()
    print("CVE archiving completed.")

if __name__ == "__main__":
    main()

