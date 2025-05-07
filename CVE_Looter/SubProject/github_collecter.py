import os
import requests
from peewee import *
from datetime import datetime
import time
import random

# Get the directory where the script is located
script_dir = os.path.dirname(os.path.realpath(__file__))

# Ensure paths are relative to the script's location
db_path = os.path.join(script_dir, "cve.sqlite")
readme_path = os.path.join(script_dir, "README.md")

db = SqliteDatabase(db_path)

class CVE_DB(Model):
    id = IntegerField()
    full_name = CharField(max_length=1024)
    description = CharField(max_length=4098)
    url = CharField(max_length=1024)
    created_at = CharField(max_length=128)

    class Meta:
        database = db

db.connect()
db.create_tables([CVE_DB])

def write_file(new_contents):
    with open(readme_path) as f:
        for _ in range(7):
            f.readline()
        old = f.read()
    new = new_contents + old
    with open(readme_path, "w") as f:
        f.write(new)

def get_info(year, pages, per_page):
    try:
        item_list = []
        api = "https://api.github.com/search/repositories?q=CVE-{}&sort=updated&per_page={}&page={}"
        for page in range(1, pages + 1):  # Go through pages as needed
            req = requests.get(api.format(year, per_page, page)).json()
            items = req.get("items", [])
            if not items:
                break
            item_list.extend(items)
            print(f"{year}: Page {page}, fetched {len(items)} entries")
            time.sleep(random.randint(3, 15))  # Random sleep to avoid API rate limits
        return item_list
    except Exception as e:
        print("Error in network request", e)
        return None

def db_match(items):
    r_list = []
    for item in items:
        id = item["id"]
        if CVE_DB.select().where(CVE_DB.id == id).count() != 0:
            continue
        full_name = item["full_name"]
        description = item["description"] or 'no description'
        url = item["html_url"]
        created_at = item["created_at"]
        r_list.append({
            "id": id,
            "full_name": full_name,
            "description": description.strip(),
            "url": url,
            "created_at": created_at
        })
        CVE_DB.create(id=id,
                      full_name=full_name,
                      description=description.strip(),
                      url=url,
                      created_at=created_at)

    return sorted(r_list, key=lambda e: e['created_at'])

def main():
    current_year = datetime.now().year
    sorted_list = []
    
    for i in range(2019, current_year + 1):  # Start from 2019 and go up to the current year
        # If the year is the current year or the previous year, fetch 3 pages of 100 entries
        if i == current_year or i == current_year - 1:
            pages = 3
            per_page = 100
        else:
            # For earlier years, fetch only 1 page of 50 entries
            pages = 1
            per_page = 50
        
        item = get_info(i, pages, per_page)
        if item is None or len(item) == 0:
            continue
        print(f"{i}: Fetched original data: {len(item)} entries")
        sorted = db_match(item)
        if len(sorted) != 0:
            print(f"{i}: Updated {len(sorted)} entries")
            sorted_list.extend(sorted)
        time.sleep(random.randint(3, 15))

    newline = ""
    for s in sorted_list:
        line = "**{}** : [{}]({})  create time: {}\n\n".format(
            s["description"], s["full_name"], s["url"], s["created_at"]
        )
        newline = line + newline

    print(newline)
    if newline != "":
        newline = "# Automatic monitor github cve using Github Actions \n\n > update time: {}  total: {} \n\n".format(
            datetime.now(),
            CVE_DB.select().where(CVE_DB.id != None).count()) + newline

        write_file(newline)

if __name__ == "__main__":
    main()
