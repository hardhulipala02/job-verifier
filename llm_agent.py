import json
import os
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

if not GOOGLE_API_KEY:
    print("ERROR: Could not find GOOGLE_API_KEY. Check your .env file!")
    exit()

client = genai.Client(api_key=GOOGLE_API_KEY)

def evaluate_email_behavior(email_body_text):
    print("Agent is analyzing the email...")
    
    prompt = f"""
    You are an expert recruitment security agent. 
    Analyze the following email text from a recruiter. 
    Look for behavioral traps or recruiting compliance anomalies.
    
    You must output your response as a JSON object with the following exact structure:
    {{
        "risk_level": "LOW, MEDIUM, or HIGH",
        "flags_detected": ["List of any red flags like requesting Telegram, fake checks, request for payment, or mismatched domains"],
        "summary": "A 1-sentence explanation of your verdict"
    }}

    EMAIL TEXT TO ANALYZE:
    "{email_body_text}"
    """
    
    response = client.models.generate_content(
        model='gemini-2.5-flash',
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
        )
    )

    scorecard = json.loads(response.text)
    print(json.dumps(scorecard, indent=4))

    return scorecard

sample_scam_email = """
Hi there! I am Ann from Qual. 
We loved your resume. We want to hire you right away for a W-2 role. 
Please message me on Telegram at @HR to do a text-based interview. 
If hired, we will mail you a check for $2,000 to buy a MacBook.
"""

evaluate_email_behavior(sample_scam_email)