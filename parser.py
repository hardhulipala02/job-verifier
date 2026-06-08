import email
import re
from email import policy

def parse_email_basics(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        msg = email.message_from_file(f, policy=policy.default)
    
    sender = msg.get("From")
    # print(f"Sender: {sender}")
    
    return msg, sender

def extract_security_headers(msg):
    auth_results = msg.get("Authentication-Results", "")
    # print(f"Raw Auth Results: \n{auth_results}\n")
    
    # Regex searches for spf, dkim, and dmarc
    dmarc_match = re.search(r"dmarc=(\w+)", auth_results, re.IGNORECASE)
    spf_match = re.search(r"spf=(\w+)", auth_results, re.IGNORECASE)
    dkim_match = re.search(r"dkim=(\w+)", auth_results, re.IGNORECASE) # NEW: Grab DKIM [cite: 676]
    
    dmarc_status = dmarc_match.group(1).lower() if dmarc_match else "missing"
    spf_status = spf_match.group(1).lower() if spf_match else "missing"
    dkim_status = dkim_match.group(1).lower() if dkim_match else "missing"
    
    print(f"DMARC: {dmarc_status} | SPF: {spf_status} | DKIM: {dkim_status}")

    return {
        "dmarc": dmarc_status,
        "spf": spf_status,
        "dkim": dkim_status
    }

# parsed_msg = parse_email_basics("test_email.eml")
# extract_security_headers(parsed_msg)