import os.path
import base64
import requests

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',  # Read-only access
    'https://www.googleapis.com/auth/gmail.modify',    # Read/write access
    'https://www.googleapis.com/auth/gmail.compose',    # Full access
    'https://www.googleapis.com/auth/gmail.labels'    # Full access

]
CREDENTIALS_FILE = 'credentials.json' 
TOKEN_FILE = 'token.json'

def init_gmail_service():
    """Shows basic usage of the Gmail API.
    Initializes and returns the Gmail API service object.
    """
    creds = None

    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            # Make sure you have your credentials.json file from Google Cloud Console
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    try:
        service = build('gmail', 'v1', credentials=creds)
        print("Succesfully connected with google")
        return service
    except HttpError as error:
        print(f'An error occurred building the service: {error}')
        return None
    
def add_label_to_message(service, message_id, label_ids_to_add):
    """Adds labels to a message."""
    if not label_ids_to_add or None in label_ids_to_add:
        print("No valid label IDs provided.")
        return None

    try:
        modify_request = {'addLabelIds': label_ids_to_add, 'removeLabelIds': []}
        message = service.users().messages().modify(
            userId='me',
            id=message_id,
            body=modify_request
        ).execute()
        return message
    except HttpError as error:
        print(f'Error modifying message: {error}')
        return None
    
    
def get_label_id(service, label_name):
    """Gets or creates the ID of a label by its name."""
    try:
        # Check existing labels
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])
        for label in labels:
            if label['name'].lower() == label_name.lower():
                return label['id']
        
        # Create the label if it doesn't exist
        print(f"Label '{label_name}' not found. Creating it...")
        label_body = {
            'name': label_name,
            'labelListVisibility': 'labelShow',
            'messageListVisibility': 'show'
        }
        created_label = service.users().labels().create(
            userId='me',
            body=label_body
        ).execute()
        return created_label['id']
    
    except HttpError as error:
        print(f'Error in get_label_id: {error}')
        return None
    
    

