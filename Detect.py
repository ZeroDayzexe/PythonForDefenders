import re
from termcolor import colored

# Define malicious patterns
malicious_domain = None # Add later
malicious_ip = None # Add later
suspicious_url_pattern = re.compile(r'\bhttps?://[^\s]+?\.(ru|cn)\b')
event_ids = ['4720', '4728', '4732', '4756']  # Common Event IDs for account creation/elevation

# Compile regex for domain, IP, and event IDs
domain_pattern = re.compile(rf'\b{malicious_domain}\b')
ip_pattern = re.compile(rf'\b{malicious_ip}\b')
event_id_pattern = re.compile(r'\b(?:' + '|'.join(event_ids) + r')\b')


with open("logfile.txt", "r") as file:
    lines = file.readlines()

# Loop through each line, search for patterns
for line_num, line in enumerate(lines, start=1):
    domain_match = domain_pattern.search(line)
    ip_match = ip_pattern.search(line)
    url_match = suspicious_url_pattern.search(line)
    event_id_match = event_id_pattern.search(line)

    # If any match is found, highlight and display it
    if domain_match or ip_match or url_match or event_id_match:
        highlighted_line = line
        
        # Highlight each match in red
        if domain_match:
            highlighted_line = highlighted_line.replace(malicious_domain, colored(malicious_domain, "red"))
        if ip_match:
            highlighted_line = highlighted_line.replace(malicious_ip, colored(malicious_ip, "red"))
        if url_match:
            highlighted_url = url_match.group(0)
            highlighted_line = highlighted_line.replace(highlighted_url, colored(highlighted_url, "red"))
        if event_id_match:
            highlighted_event_id = event_id_match.group(0)
            highlighted_line = highlighted_line.replace(highlighted_event_id, colored(highlighted_event_id, "red"))

        print(f"Match found on line {line_num}: {highlighted_line.strip()}")
