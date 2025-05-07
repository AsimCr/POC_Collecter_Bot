import telebot
import json
from telebot import types
from search import find_cve, extract_cve_urls  # Import the find_cve and extract_cve_urls functions from search.py
import signal
import sys
import os
import time


script_dir = os.path.dirname(os.path.realpath(__file__))
NEWSLETTER_FILE = os.path.join(script_dir, "Newsletter_Sub.json")
Storage_Path = script_dir+"/StorageFiles"


API_KEY = "YOUR_TELEGRAM_API_KEY"
bot = telebot.TeleBot(API_KEY)


# Load CVEs from JSON file
def load_cves():
    try:
        with open(os.path.join(Storage_Path, "cves.json"), 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return []

# Save CVEs to JSON file
def save_cves(cves):
    with open(os.path.join(Storage_Path, "cves.json"), 'w') as file:
        json.dump(cves, file, indent=4)


# /start command handler
@bot.message_handler(commands=['start'])
def handle_start(message):
    bot.reply_to(message, (
        "Welcome to Six Eyes bot\n\n"
        "Your fastest way to monitor the POCs of any CVE on the internet, even the deleted ones 😉\n\n"
        "- You can use /help to list all possible commands.\n"
        "- You can use /search {CVE Name} to search for the POC of any CVE you need.\n"
        "- You can also use /add_cve {CVE Name} to monitor the internet for the POC of any CVE you need, "
        "and the bot will alert you whenever found.\n\n"
        "This is a private bot; only authorized users by admin can use this bot."
    ))


def load_subscribers():
    if not os.path.exists(NEWSLETTER_FILE):
        return []
    with open(NEWSLETTER_FILE, 'r') as f:
        return json.load(f)

def save_subscribers(data):
    with open(NEWSLETTER_FILE, 'w') as f:
        json.dump(data, f, indent=4)

@bot.message_handler(commands=['subscribe', 'Subscribe'])
def subscribe_user(message):
    log_message(message)
    if is_user_allowed(message.from_user):
        subscribers = load_subscribers()
        chat_id = str(message.chat.id)
        username = message.from_user.username or "unknown"

        if any(sub['chat_id'] == chat_id for sub in subscribers):
            bot.reply_to(message, "You're already subscribed to the newsletter.")
            return

        next_id = max((sub['id'] for sub in subscribers), default=0) + 1
        subscribers.append({
            "id": next_id,
            "name": username,
            "chat_id": chat_id
        })
        save_subscribers(subscribers)
        bot.reply_to(message, "You've been subscribed to the newsletter.")

@bot.message_handler(commands=['unsubscribe', 'Unsubscribe'])
def unsubscribe_user(message):
    log_message(message)
    if is_user_allowed(message.from_user):
        chat_id = str(message.chat.id)
        subscribers = load_subscribers()
        new_subscribers = [sub for sub in subscribers if sub['chat_id'] != chat_id]

        if len(new_subscribers) == len(subscribers):
            bot.reply_to(message, "You're not subscribed.")
        else:
            save_subscribers(new_subscribers)
            bot.reply_to(message, "You've been unsubscribed from the newsletter.")


# /add_cve command
@bot.message_handler(commands=['add_cve', 'add_CVE', 'Add_cve', 'Add_CVE'])
def add_cve(message):
    try:
        cve_name = message.text.split()[1]
        cves = load_cves()
        
        # Check if the CVE already exists for the user
        for cve in cves:
            if cve["cve_name"].lower() == cve_name.lower() and cve["username"] == message.from_user.username:
                bot.reply_to(message, f"CVE {cve_name} is already in your list.")
                return
        
        # Perform a search without returning the output
        search_results = find_cve(cve_name)
        if search_results:
            # If there are results, prompt the user with options
            markup = types.InlineKeyboardMarkup()
            add_button = types.InlineKeyboardButton(f"Add CVE {cve_name}", callback_data=f"force_add_cve_{cve_name}")
            search_button = types.InlineKeyboardButton(f"Search CVE {cve_name}", callback_data=f"search_cve_{cve_name}")
            markup.add(add_button, search_button)
            bot.reply_to(message, f"There are some results in the DB. Are you sure you want to add this CVE to the watch list?", reply_markup=markup)
        else:
            # If no results, add the CVE as usual
            cves.append({"cve_name": cve_name, "username": message.from_user.username, "chat_id": message.chat.id})
            save_cves(cves)
            bot.reply_to(message, f"{cve_name} added successfully.")
    
    except IndexError:
        bot.reply_to(message, "Please provide a CVE name.")







# /del_cve command
@bot.message_handler(commands=['del_cve', 'Del_CVE'])
def del_cve(message):
    try:
        cve_name = message.text.split()[1]
        cves = load_cves()
        # Delete the CVE only for the user who requested it
        cves = [cve for cve in cves if not (cve["cve_name"].lower() == cve_name.lower() and cve["username"] == message.from_user.username)]
        save_cves(cves)
        bot.reply_to(message, f"CVE {cve_name} deleted successfully.")
    except IndexError:
        bot.reply_to(message, "Please provide a CVE name.")




# /list_cve command
@bot.message_handler(commands=['list_cve', 'List_CVE'])
def list_cve(message):
    username = message.from_user.username
    cves = load_cves()
    user_cves = [cve['cve_name'] for cve in cves if cve['username'] == username]
    if user_cves:
        bot.reply_to(message, "Your CVEs:\n" + "\n".join(user_cves))
    else:
        bot.reply_to(message, "You have no CVEs in your list.")

# /flush_cve command
@bot.message_handler(commands=['flush_cve', 'Flush_CVE'])
def flush_cve(message):
    username = message.from_user.username
    cves = load_cves()
    cves = [cve for cve in cves if cve['username'] != username]
    save_cves(cves)
    bot.reply_to(message, "All your CVEs have been deleted.")

# /help command for admin and authorized users
@bot.message_handler(commands=['help', 'Help'])
def help_command(message):
    help_text = (
        "/search <query> - Search for CVEs\n"
        "/add_cve <cve_name> - Add a CVE to watch\n"
        "/del_cve <cve_name> - Delete a CVE from watch list\n"
        "/list_cve - List all your CVEs\n"
        "/flush_cve - Delete all your CVEs\n"
        "/help - Show this help message"
    )
    bot.reply_to(message, help_text)


# Now, define your specific command handler
@bot.message_handler(commands=['search', 'Search'])
def search_command(message):
    try:
        query = " ".join(message.text.split()[1:])
        if not query.startswith("CVE"):
            bot.reply_to(message, "Search query must be in this format'CVE-0000-00000'.")
            return
        
        results = find_cve(query)
        if not results:
            urls = extract_cve_urls(query)
            if urls:
                message_text = (
                    "Your requested CVE seems old (If not, please contact the admin), "
                    "anyway here is something that might help you:\n" +
                    "\n".join(urls[:10])
                )
                bot.reply_to(message, message_text)
            else:
                markup = types.InlineKeyboardMarkup()
                add_button = types.InlineKeyboardButton(f"Add CVE {query}", callback_data=f"add_cve_{query}")
                markup.add(add_button)
                bot.reply_to(message, f"No results found for {query}. Would you like to add it?", reply_markup=markup)
            return

        send_search_results(message, query, results, start_index=0)
    except IndexError:
        bot.reply_to(message, "Please provide a search query.")

 
        


def send_search_results(message, query, results, start_index):
    chunk = results[start_index:start_index + 3]
    if not chunk:
        return

    for item in chunk:
        bot.send_message(message.chat.id, item)

    if start_index + 3 < len(results):
        markup = types.InlineKeyboardMarkup()
        more_button = types.InlineKeyboardButton("More", callback_data=f"more_{start_index + 3}_{query}")
        enough_button = types.InlineKeyboardButton("Enough", callback_data="enough")
        markup.add(more_button, enough_button)
        bot.send_message(message.chat.id, "Do you want more results?", reply_markup=markup)
    else:
        bot.send_message(message.chat.id, "End of results.")
        



@bot.callback_query_handler(func=lambda call: call.data.startswith("more_") or call.data == "enough")
def handle_more_or_enough(call):
    if call.data.startswith("more_"):
        query = call.data.split("_", 2)[2]
        start_index = int(call.data.split("_", 2)[1])
        results = find_cve(query)
        send_search_results(call.message, query, results, start_index)
    # Remove buttons after any selection
    bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=None)

    
          
          
          

@bot.callback_query_handler(func=lambda call: call.data.startswith("force_add_cve_"))
def handle_force_add_cve(call):
    # Extract the correct CVE name without the "force_add_cve_" prefix
    cve_name = call.data[len("force_add_cve_"):]
    cves = load_cves()

    # Add the CVE to the user's watch list
    cves.append({"cve_name": cve_name, "username": call.from_user.username, "chat_id": call.message.chat.id})
    save_cves(cves)
    bot.send_message(call.message.chat.id, f"{cve_name} added successfully to the watch list.")
    bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=None)



@bot.callback_query_handler(func=lambda call: call.data.startswith("search_cve_"))
def handle_search_cve(call):
    cve_name = call.data.split("_", 2)[2]
    results = find_cve(cve_name)
    send_search_results(call.message, cve_name, results, start_index=0)
    bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=None)









@bot.callback_query_handler(func=lambda call: call.data.startswith("delete_"))
def handle_delete_cve(call):
    cve_name = call.data.split("_", 1)[1]
    cves = load_cves()
    
    # Remove the CVE from the list
    cves = [cve for cve in cves if cve["cve_name"].lower() != cve_name.lower() or cve["username"] != call.from_user.username]
    save_cves(cves)
    
    bot.send_message(call.message.chat.id, f"CVE {cve_name} has been deleted from the watch list.")
    bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=None)
    
    
    
    
    
    






@bot.callback_query_handler(func=lambda call: call.data.startswith("add_cve_"))
def handle_add_cve_callback(call):
    cve_name = call.data.split("_", 2)[2]
    cves = load_cves()

    # Check if the CVE already exists for the user
    for cve in cves:
        if cve["cve_name"].lower() == cve_name.lower() and cve["username"] == call.from_user.username:
            bot.send_message(call.message.chat.id, f"CVE {cve_name} is already in your list.")
            bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=None)
            return

    # Add the new CVE if it doesn't exist
    cves.append({"cve_name": cve_name, "username": call.from_user.username, "chat_id": call.message.chat.id})
    save_cves(cves)
    bot.send_message(call.message.chat.id, f"{cve_name} added successfully to the watch list.")
    bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=None)
    

# Graceful shutdown on CTRL+C
def shutdown(signal, frame):
    print("Shutting down gracefully...")
    bot.stop_polling()
    sys.exit(0)

# Register the signal handlers for graceful shutdown
signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)

def start_polling():
    while True:
        try:
            bot.polling(none_stop=True, interval=0, timeout=20)
        except Exception as e:
            time.sleep(15) 
            pass
            


if __name__ == "__main__":
    start_polling()

