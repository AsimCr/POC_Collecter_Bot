import os
import glob
import re


script_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(script_dir)



def find_cve(cve_name):
    # Define the root directories to search in
    root_dirs = [parent_dir+'/CVE_Looter/2025', parent_dir+'/CVE_Looter/CVE_Archive']
    
    # Store results
    results = []
    
    # Search each directory
    for root in root_dirs:
        # Construct the path pattern to search for
        search_path = os.path.join(root, '**', cve_name, '**')
        
        # Use glob to find matching subdirectories
        for dir_path in glob.glob(search_path, recursive=True):
            # Check if it's a directory
            if os.path.isdir(dir_path):
                # Get all files in the directory
                files = os.listdir(dir_path)
                
                # Check if there are more than one file in the subfolder
                if len(files) > 1:
                    # Try to read the content of "This_Is_The_CVE_URL"
                    url_file_path = os.path.join(dir_path, 'This_Is_The_CVE_URL')
                    if os.path.exists(url_file_path):
                        with open(url_file_path, 'r') as file:
                            cve_url = file.read().strip()
                        # Append the directory path and the CVE URL to results
                        results.append(cve_url)
    
    return results
    

def extract_cve_urls(cve_name, file_path=os.path.join(script_dir+"/StorageFiles", "Old_CVEs.md")):
    url_pattern = r'(https://github\.com/[^)]+)\)'
    urls = []

    with open(file_path, 'r') as file:
        for line in file:
            if cve_name in line:
                matches = re.findall(url_pattern, line)
                urls.extend(matches)
    
    return urls
