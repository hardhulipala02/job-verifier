import email
from email import policy

def parse_email_basics(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        msg = email.message_from_file(f, policy=policy.default)
    
    sender = msg.get("From")
    print(f"Sender: {sender}")
    
    return msg

parsed_msg = parse_email_basics("test_email.eml")