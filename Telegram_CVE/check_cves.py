import json
import os
from telebot import TeleBot, types
from search import find_cve  # Import the find_cve function from search.py

script_dir = os.path.dirname(os.path.realpath(__file__))
Storage_dir = script_dir+"/StorageFiles"

API_KEY = "YOUR_TELEGRAM_API_KEY"
bot = TeleBot(API_KEY)

# Path to the JSON file for storing sent URLs

SENT_URLS_FILE = os.path.join(Storage_dir, "sent_urls.json")

# Load CVEs from JSON file
def load_cves():
    try:
        with open(os.path.join(Storage_dir, "cves.json"), 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return []

# Save CVEs to JSON file
def save_cves(cves):
    with open(os.path.join(Storage_dir, "cves.json"), 'w') as file:
        json.dump(cves, file, indent=4)

# Load sent URLs for all users
def load_sent_urls():
    if not os.path.exists(SENT_URLS_FILE):
        return {}
    
    with open(SENT_URLS_FILE, 'r') as file:
        print(SENT_URLS_FILE)
        return json.load(file)

# Save sent URLs for all users
def save_sent_urls(sent_urls):
    with open(SENT_URLS_FILE, 'w') as file:
        json.dump(sent_urls, file, indent=4)

# Log a sent URL to avoid sending it again (per user)
def log_sent_url(username, url):
    sent_urls = load_sent_urls()
    
    if username not in sent_urls:
        sent_urls[username] = []
    
    sent_urls[username].append(url)
    save_sent_urls(sent_urls)

# Function to check for CVEs and notify users
def check_cves():
    cves = load_cves()
    sent_urls = load_sent_urls()
    
    for cve_entry in cves:
        username = cve_entry["username"]
        chat_id = cve_entry["chat_id"]
        results = find_cve(cve_entry["cve_name"])
        
        if username in sent_urls:
            user_sent_urls = sent_urls[username]
        else:
            user_sent_urls = []
        
        new_results = [url for url in results if url not in user_sent_urls]
        
        if new_results:
            message = f"Results found for {cve_entry['cve_name']}:\n" + "\n".join(new_results)
            markup = types.InlineKeyboardMarkup()
            delete_button = types.InlineKeyboardButton(f"Delete {cve_entry['cve_name']}", callback_data=f"delete_{cve_entry['cve_name']}")
            markup.add(delete_button)
            bot.send_message(chat_id, message, reply_markup=markup)
            
            # Log the sent URLs per user
            for url in new_results:
                log_sent_url(username, url)

if __name__ == "__main__":
    check_cves()

