import os.path
import base64
import requests
from typing import List
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


import re # <-- Import regex module
import json # <-- Import json module
from collections import Counter # <-- Import Counter for easy counting
from referencing import Resource # <-- Import time module (optional, for potential delays)


PHISHING_KEYWORDS = keywords = [
    "access",
    "accounts",
    "auth",
    "security",
    "portal",
    "user",
    "company",
    "admin",
    "credential",
    "identity",
    "login",
    "password",
    "privilege",
    "token",
    "validation",
    "assurance",
    "availability",
    "confidentiality",
    "integrity",
    "privacy",
    "safety",
    "trust",
    "verification",
    "check",
    "key",
    "lock",
    "biometrics",
    "authorize",
    "authentication",
    "session",
    "profile",
    "service",
    "support",
    "notify",
    "email",
    "account",
    "update",
    "secure",
    "notification",
    "transaction",
    "validate",
    "confirmation",
    "manager",
    "assistant",
    "dashboard",
    "information",
    "communication",
    "finance",
    "maintenance",
    "customer",
    "invoice",
    "billing",
    "subscription",
    "order",
    "shipment",
    "purchase",
    "alert",
    "billinginfo",
    "receipt",
    "accountinfo",
    "payment",
    "invoiceinfo",
    "orderinfo"
]

global PHISHING_LINKS

global unwanted_extentions


def import_data():
    global PHISHING_LINKS
    global unwanted_extentions

    with open('Data/phishing-links-NEW-today.txt', 'r') as file:
        PHISHING_LINKS = [PHISHING_LINKS.strip() for PHISHING_LINKS in file if PHISHING_LINKS.strip()]
    with open('Data/unwated_extensions.txt', 'r') as file:
        unwanted_extentions = [unwanted_extentions.strip() for unwanted_extentions in file if unwanted_extentions.strip()]

def check_key_words(email_item):
    body = email_item['body']
    subject = email_item['subject']

    text_lower = body.lower()
    found = [word for word in PHISHING_KEYWORDS if word in text_lower]
    text_lower = subject.lower()
    found += [word for word in PHISHING_KEYWORDS if word in text_lower]
    return len(found)

def check_link(link):
    global PHISHING_LINKS
    text_lower = link.lower()
    for plink in PHISHING_LINKS:
        if(link == plink):
            return 10
        
def check_dmarc(email_item):
    if(email_item["dmarc"] == ['dmarc=pass']):
        return 0
    if(email_item["dmarc"] == None):
        return 5
    return 10

def check_spf(email_item):
    if(email_item["spf"][:4] == "pass"):
        return 0
    elif(email_item["spf"] == None):
        return 5
    else:
        return 10
    
def check_dkim(email_item):
    if(email_item["dkim"] == ['dkim=pass']):
        return 0
    if(email_item["dkim"] == None):
        return 5
    return 10
    
def query_urlhaus(url, auth_key):

    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    
    headers = {}
    if auth_key:
        headers["Auth-Key"] = auth_key
    
    data = {"url": url}
    
    try:
        response = requests.post(api_url, headers=headers, data=data)
        response.raise_for_status()  # Raise exception for bad status codes
        temp = response.json()
        threat_status = temp.get('url_status')
        threat_type =  temp.get('threat')
        response_item = {
            "threat_status" : threat_status,
            "threat_type" : threat_type
        }
        return response_item
    except requests.exceptions.RequestException as e:
        print(f"Error querying URLhaus: {e}")
        return None
    
def check_urls(urls, api_key):
    for url in urls:
        results = query_urlhaus(url,api_key)
        threat_status = results['threat_status']
        threat_type = results['threat_type']
        
        if(threat_status != None):
            return (50, {"status":threat_status,"type":threat_type})
    return (0, {"status":None,"type":None})



def get_email_body(service, msg_id, user_id = 'me'):
   
    if not msg_id:
        print("Error: Message ID is required for get_email_body.")
        return None
    if not service:
        print("Error: Gmail service instance is required.")
        return None

    try:
        message = service.users().messages().get(userId=user_id, id=msg_id, format='full').execute()
        payload = message.get('payload')
        if not payload:
            print(f"Could not find payload in message ID: {msg_id}")
            return "" # Return empty string if no payload

        body_content = ""
        parts_to_process = [payload] # Use a list as a stack/queue

        while parts_to_process:
            part = parts_to_process.pop(0) # Process in FIFO order (breadth-first like)
            mimeType = part.get('mimeType', '')
            data = part.get('body', {}).get('data')
            filename = part.get('filename')

            # Skip attachments unless they are text-based inline parts without a filename
            if filename and filename != "":
                 continue

            if data: # Only process parts with actual data in the body
                if mimeType == 'text/plain':
                    try:
                        decoded_data = base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')
                        body_content += decoded_data + "\n"
                    except Exception as decode_error:
                        print(f"Error decoding text/plain part: {decode_error}")
                elif mimeType == 'text/html':
                     try:
                        html_content = base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')
                        # Optional: Use BeautifulSoup here if complex HTML parsing is needed
                        # soup = BeautifulSoup(html_content, 'html.parser')
                        # body_content += soup.get_text(separator='\n') + "\n"
                        # Simpler: Add raw HTML for regex extraction
                        body_content += html_content + "\n"
                     except Exception as decode_error:
                        print(f"Error decoding text/html part: {decode_error}")

            # If the part is multipart, add its sub-parts to the list for processing
            if 'parts' in part:
                parts_to_process.extend(part.get('parts', []))

        # Fallback for simple non-multipart messages if no content found yet
        if not body_content and payload.get('body', {}).get('data'):
             data = payload.get('body', {}).get('data')
             mimeType = payload.get('mimeType', '')
             if data and ('text/plain' in mimeType or 'text/html' in mimeType) :
                  try:
                     decoded_data = base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')
                     body_content = decoded_data
                  except Exception as decode_error:
                      print(f"Error decoding fallback body data: {decode_error}")

        if not body_content:
             print(f"Warning: Could not extract text/plain or text/html body content for message ID: {msg_id}")
             return "" # Return empty string if no useful content found

        return body_content

    except HttpError as error:
        print(f'An HTTP error occurred getting message {msg_id}: {error}')
        # Check for common errors like 404 Not Found
        if error.resp.status == 404:
            print(f"Message with ID '{msg_id}' not found.")
        return None
    except Exception as e:
        print(f'An unexpected error occurred getting message {msg_id}: {e}')
        return None


def extract_urls(text) -> List[str]:

    if not text:
        return []

    # Improved regex: handles more edge cases like URLs in parentheses or quotes
    # Still not perfect, but better. Includes http, https, ftp, and www.
    url_pattern = re.compile(
        r'((?:https?|ftp)://[^\s/$.?#].[^\s<>\"]*|www\.[^\s<>\"]+)'
    )
    # Find all non-overlapping matches
    urls = url_pattern.findall(text)

    cleaned_urls = set() # Use a set for automatic deduplication
    for url in urls:
        # Basic cleanup: remove trailing punctuation common in sentences
        # Careful not to remove punctuation that's part of the URL path/query/fragment
        cleaned_url = url
        while cleaned_url and cleaned_url[-1] in '.,;!?)\]}>':
            # Check if the char before the punctuation is alphanumeric or a valid URL path char
            if len(cleaned_url) > 1 and (cleaned_url[-2].isalnum() or cleaned_url[-2] in '/#?=&%'):
                 cleaned_url = cleaned_url[:-1]
            else:
                 break # Stop if removing might break the URL

        # Ensure 'www.' links have a scheme (default to http)
        if cleaned_url.startswith('www.'):
            cleaned_urls.add('http://' + cleaned_url)
        else:
            cleaned_urls.add(cleaned_url)

    return list(cleaned_urls)


def fetch_and_extract_urls(service, message_id):

    email_body = get_email_body(service, msg_id=message_id)

    if email_body is None:
        # Error occurred during fetch, get_email_body already printed details
        return []
    elif not email_body:
        print("Email body was empty or could not be extracted.")
        return []
    else:
        # print("\n--- Email Body Extracted (Snippet) ---")
        # print(email_body[:500] + "..." if len(email_body) > 500 else email_body)
        # print("--- End Snippet ---")
        urls_found = extract_urls(email_body)
        return urls_found


def common_file_names_check(payload):
    global unwanted_extentions
    filenames = []
    malicious_file_score = 0
    parts = payload.get('parts')
    if parts != None:
        for y in parts:
            if y.get('filename') == '':
                filename = "Filename has not been found"
                filenames.append(filename)
            else:
                filenames.append(y.get('filename'))

        for x in filenames:
            extensions = re.findall(r'(.[a-zA-Z0-9]+)$', x)

        for j in extensions:
            if j in unwanted_extentions:
                malicious_file_score += 15
                
    return malicious_file_score