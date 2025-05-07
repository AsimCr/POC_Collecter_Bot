import json
import os
import requests
from telebot import TeleBot
from bs4 import BeautifulSoup
from search import extract_cve_urls
from datetime import datetime



script_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(script_dir)
Storage_dir = script_dir+"/StorageFiles"


# Telegram Bot API Key
API_KEY = "YOUR_TELEGRAM_API_KEY"
bot = TeleBot(API_KEY)


# Get the current year, month, and day
now = datetime.now()
year = now.strftime("%Y")
month = now.strftime("%m")
day = now.strftime("%d")
severity_Num = 8
#day = "13"

# Create the full path to the current day folder
day_folder = os.path.join(parent_dir+"/CVE_Looter", year, month, day)
# Step 3: Check if the day folder exists
if not os.path.exists(day_folder):
    print("Day folder does not exist. Exiting script.")
    exit()

# Function to load sent CVEs from log file
def load_sent_log():
    with open(Storage_dir+"/Sent_Newsletter.json", 'r') as file:
        return json.load(file)

# Function to save sent CVEs to log file
def save_sent_log(sent_log):
    with open(Storage_dir+"/Sent_Newsletter.json", 'w') as file:
        json.dump(sent_log, file, indent=4)

# Function to fetch NVD data (Base Score and Description)
def fetch_nvd_details(cve_name):
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_name}"
    headers = { "User-Agent": "Mozilla/5.0", "Accept": "text/html", "Accept-Language": "en-US,en;q=0.9" }
    try:
        response = requests.get(nvd_url, headers=headers)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, "html.parser")
            
            # Extract Base Score
            score_tag = soup.find("a", class_="label label-danger")
            score = float(score_tag.get_text().split()[0]) if score_tag else None
            
            # Extract Description
            description_tag = soup.find("p", {"data-testid": "vuln-description"})
            description = description_tag.text.strip() if description_tag else "Description not available"
            
            return score, description
    except Exception as e:
        print(f"Error fetching from NVD: {e}")
    return None, "Description not available"

# Function to process CVE folders
def process_cve_folders():
    sent_log = load_sent_log()

    for cve_folder in os.listdir(day_folder):
        cve_path = os.path.join(day_folder, cve_folder)

        # Check if the folder contains a subfolder named '1'
        one_folder_path = os.path.join(cve_path, "1")
        if not os.path.isdir(one_folder_path):
            continue  # Skip if no folder named '1'

        # Check if the "1" folder contains more than one file
        files_in_one_folder = os.listdir(one_folder_path)
        if len(files_in_one_folder) <= 1:
            continue  # Skip if there is only one or fewer files

        # Check if "This_Is_The_CVE_URL" file exists in the "1" folder
        url_file_path = os.path.join(one_folder_path, "This_Is_The_CVE_URL")
        if not os.path.isfile(url_file_path):
            continue  # Skip if the URL file does not exist

        # Extract URLs using extract_cve_urls function
        urls = extract_cve_urls(cve_folder)
        if urls:
            continue  # Skip to the next CVE if URLs are found

        # Step 2: Read content from "This_Is_The_CVE_URL" file
        with open(url_file_path, 'r') as url_file:
            cve_url_content = url_file.read().strip()

        # Fetch NVD details (score and description)
        score, description = fetch_nvd_details(cve_folder)

        # Generate the report using the Report_Creater function (with severity)
        report, severity = Report_Creater(cve_folder, cve_url_content, description, score)
        print(score)

        # Skip if the severity is below 7, unless severity is unavailable
        if severity is not None and severity < severity_Num:
            continue

        # Send the report to users and log it
        send_report_to_users(cve_folder, report, sent_log)
    # Save the updated sent log
    save_sent_log(sent_log)

# Function to create a report for a CVE (returns report and severity)
def Report_Creater(CVE_Name, CVE_URL_Content, CVE_NVD_Description, CVE_NVD_Severity):
    if CVE_NVD_Severity is None:
        severity = None
    else:
        severity = CVE_NVD_Severity
    
    report = (
        f"I thought you might be interested\n"
        f"Here is the first published POC of the {CVE_Name}, which is {CVE_NVD_Description},\n\n"
        f"Here is the POC link: {CVE_URL_Content}"
    )
    return report, severity

# Function to load users from the newsletter JSON file
def load_users():
    with open(Storage_dir+"/Newsletter_Sub.json", 'r') as file:
        return json.load(file)

# Function to send the report to users and log sent CVEs
def send_report_to_users(cve_folder, report, sent_log):
    users = load_users()
    if not users:
        print("No users found in the newsletter.")
        return

    for user in users:
        chat_id = user['chat_id']
        user_id = str(user['id'])  # Ensure user_id is a string (JSON keys must be strings)

        # Initialize user log if it doesn't exist
        if user_id not in sent_log:
            sent_log[user_id] = []

        # Skip if the CVE has already been sent to this user
        if cve_folder in sent_log[user_id]:
            continue

        # Send the report to the user via Telegram
        send_report(chat_id, report)

        # Log the CVE as sent for this user
        sent_log[user_id].append(cve_folder)

# Function to send a report to a user via Telegram
def send_report(chat_id, report):
    bot.send_message(chat_id, report)
    print(f"Report sent to user with chat ID: {chat_id}")

def send_welcome(chat_id):
    report = (
        f"Welcome, \n"
        f"You have been added by the admin to the Six Eyes newsletter, Contact the admin if you want to be removed.\n\n"
        f"Note: This is the first stage, missing/bad CVE description could occur, It will be updated later.."
    )

    bot.send_message(chat_id, report)
# Execute the function to process CVEs and send reports
if __name__ == "__main__":
    process_cve_folders()
