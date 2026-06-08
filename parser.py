import email
import re
from email import policy

def parse_email_basics(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        msg = email.message_from_file(f, policy=policy.default)
    
    sender = msg.get("From")
    print(f"Sender: {sender}")
    
    return msg

def extract_security_headers(msg):
    auth_results = msg.get("Authentication-Results", "")
    print(f"Raw Auth Results: \n{auth_results}\n")
    
    # regex for spf=pass; dkim=pass; dmarc=fail header.from=domain.com
    dmarc_match = re.search(r"dmarc=(\w+)", auth_results, re.IGNORECASE)
    spf_match = re.search(r"spf=(\w+)", auth_results, re.IGNORECASE)
    
    dmarc_status = dmarc_match.group(1).lower() if dmarc_match else "missing"
    spf_status = spf_match.group(1).lower() if spf_match else "missing"
    
    print(f"DMARC Status: {dmarc_status}")
    print(f"SPF Status: {spf_status}")

parsed_msg = parse_email_basics("test_email.eml")
extract_security_headers(parsed_msg)