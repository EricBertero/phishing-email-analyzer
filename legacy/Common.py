import re
import base64
from email import policy
from email.parser import BytesParser
from email.generator import BytesGenerator
import io

def extract_header_components(header,body, message_id, payload):
    message_info = []
    
    date = ''
    spf = ''
    dkim = ''
    dmarc = ''
    returning_path = ''
    from_field = ''
    subject_field = ''
    to_field = ''
    received = ''
    
    for i in header:
        if i.get('name') == "Authentication-Results":
            index = header.index(i)
            temp = header[index]
            dmarc = re.findall(r'dmarc=pass|dmarc=fail', temp.get('value'))
        elif dmarc == '' or dmarc == 'none':
            dmarc = 'none'
            
        if i.get('name') == "Authentication-Results":
            index = header.index(i)
            temp = header[index]
            spf = re.findall(r'spf=pass|spf=fail', temp.get('value'))
        elif spf == '' or spf == 'none':
            spf = 'none'
            
        if i.get('name') == "Authentication-Results":
            index = header.index(i)
            temp = header[index]
            dkim = re.findall(r'dkim=pass|dkim=fail', temp.get('value'))
        elif dkim == '' or dkim == 'none':
            dkim = 'none'
            
        if i.get('name') == "Return-Path":
            index = header.index(i)
            returning_path = header[index].get('value')
        elif returning_path == '' or returning_path == 'none':
            returning_path = 'none'
            
        if i.get('name') == "From":
            index = header.index(i)
            temp = header[index] 
            from_field = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', temp.get('value'))
        elif from_field == '' or from_field == 'none':
            from_field = 'none'
        
        if i.get('name') == "Subject":
            index = header.index(i)
            subject_field = header[index].get('value')
        elif subject_field == '' or subject_field == 'none':
            subject_field = 'none'
        
        if i.get('name') == "To":
            index = header.index(i)
            to_field = header[index].get('value')
        elif to_field == '' or to_field == 'none':
            to_field = 'none'
        
        if i.get('name') == "Received":
            index = header.index(i)
            temp = header[index]
            received = re.findall(r'(?:from|by)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', temp.get('value'))
        elif received == '' or received == 'none':
            received = 'none'
        
        if i.get('name') == "Date":
            index = header.index(i)
            date = header[index].get('value')
        elif date == '' or date == 'none':
            date = 'none'
 
    new_item = {
        "message_id" : message_id,
        "date": date,
        "subject" : subject_field,
        "from" : from_field,
        "to" : to_field,
        "dmarc" : dmarc,
        "spf" : spf,
        "dkim" : dkim,
        "return_path" : returning_path,
        "received" : received,
        "body" : body,
        "payload": payload,
        "threat_status":"",
        "threat_type":"",
        "KEY_WORDS_FAIL":"Pass",
        "DKIM_FAIL":"Pass",
        "DMARC_FAIL":"Pass",
        "SPF_FAIL":"Pass",
        "URLHAUS_FAIL":"Pass",
        "EXTENSIONS_FAIL":"Pass"
    }
    
    return new_item
        
def get_decoded_body(part):
    """Decodes the base64 encoded email body part."""
    body_data = part.get('body', {}).get('data')
    if body_data:
        try:
            decoded_bytes = base64.urlsafe_b64decode(body_data.encode('ASCII'))
            return decoded_bytes.decode('utf-8', errors='replace')
        except (ValueError, TypeError, base64.binascii.Error) as e:
            print(f"Error decoding base64 body part: {e}")
            return "" 
        except UnicodeDecodeError as e:
             print(f"Error decoding body part content to text: {e}")
             return ""
    return ""

def extract_body_text(parts):
    """Recursively extracts text content (plain and HTML) from MIME parts."""
    body_text = ""
    if parts:
        for part in parts:
            mime_type = part.get('mimeType', '')
            if mime_type == 'text/plain':
                body_text += get_decoded_body(part) + "\n"
            elif mime_type == 'text/html':
                
                body_text += get_decoded_body(part) + "\n"
            elif 'parts' in part:
                body_text += extract_body_text(part['parts'])
    return body_text

    
def gmail_pharser(message_id, service):
    
        message_response = service.users().messages().get(
            userId='me',
            id=message_id,
            format='full'
        ).execute()

        payload = message_response['payload']
        header = payload.get('headers', [])
        body = payload.get('body', [])
        parts = payload.get('parts', [])
        
        body = extract_body_text(payload.get('parts', []))
        
        return (header,body,parts, payload)
        

def import_eml_message(eml_path, service):
    """Import an EML file into Gmail using the same style as messages().get()"""

    with open(eml_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    
    original_message_id = msg['Message-ID']
    
    # Rebuild raw message
    buffer = io.BytesIO()
    BytesGenerator(buffer, policy=policy.default).flatten(msg)
    raw = base64.urlsafe_b64encode(buffer.getvalue()).decode()

    # Import with custom metadata
    message_response = service.users().messages().import_(
        userId='me',
        body={
            'raw': raw,
            'labelIds': ['INBOX'],
            'internalDateSource': 'dateHeader', 
            'payload': {
                'headers': [{
                    'name': 'X-Original-Message-ID',
                    'value': original_message_id
                }]
            }
        }
    ).execute()

    # Add original ID to response
    message_response['originalMessageId'] = original_message_id
    message_response['gmailMessageId'] = message_response['id']

    #print(f"Original ID: {original_message_id}")
    #print(f"Gmail ID: {message_response['id']}")
    return message_response
 