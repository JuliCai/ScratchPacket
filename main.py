import scratchattach as sa
from scratchpacket import packet, response
import time
import traceback
import random


"""
CHANGE THESE VARIABLES:
"""
project_id = "1225704696"  # Replace with your Scratch project ID
logfile_path = "logs.txt"  # Path to your log file
useragent = "library: scratchpacket/1.0 by jhalloran | cloud bot by YOUR NAME"  # User agent for Scratch requests
debug = True # Whether to print debug stuff (not recommended outside development)
basicprints = True # Whether to print basic status/lifecycle updates (recommended for running locally, not recommended for servers)


"""c
DO CHANGE THESE VARIABLES:
"""
requests = []
responsestoping = []
cloud = sa.get_tw_cloud(project_id, purpose = useragent)

import scratchattach as sa
import time


def get_cloud_var(cloud_object, var_name):
    """
    Retrieves the value of a single cloud variable from a Scratch project.

    Args:
        cloud_object: An instance of a scratchattach cloud object (e.g., sa.get_tw_cloud(...)).
        var_name (str): The name of the cloud variable to retrieve.

    Returns:
        str or None: The value of the cloud variable if it exists, otherwise None.
    """
    try:
        all_vars = cloud_object.get_all_vars()
        return all_vars.get(var_name, None)
    except Exception as e:
        print(f"Error fetching all cloud variables: {e}")
        return None

# Encoding/decoding functions for ScratchAttach cloud variable handling

# First, the character-to-code mapping for number encoding
# (Based on the provided table: 10-71, skipping 1-9 for two-digit consistency)
# Use lowercase letter keys so functions normalize input to lowercase before processing.
char_to_code = {
    'a': 10, 'b': 11, 'c': 12, 'd': 13, 'e': 14, 'f': 15, 'g': 16, 'h': 17, 'i': 18, 'j': 19,
    'k': 20, 'l': 21, 'm': 22, 'n': 23, 'o': 24, 'p': 25, 'q': 26, 'r': 27, 's': 28, 't': 29,
    'u': 30, 'v': 31, 'w': 32, 'x': 33, 'y': 34, 'z': 35,
    '1': 36, '2': 37, '3': 38, '4': 39, '5': 40, '6': 41, '7': 42, '8': 43, '9': 44, '0': 45,
    '_': 46,
    ' ': 47,  # space
    '!': 48,
    '.': 49,
    ',': 50,
    '-': 51,
    '@': 52,
    '#': 53,
    '$': 54,
    '%': 55,
    '&': 56,
    '*': 57,
    '(': 58,
    ')': 59,
    '+': 60,
    '=': 61,
    ':': 62,
    ';': 63,
    "'": 64,
    '"': 65,
    '?': 66,
    '|': 67,
    '\\': 68,  # literal backslash
    '/': 69,
    '<': 70,
    '>': 71,
}

# Reverse mapping for decoding
# This will map numeric codes back to their representative characters (lowercase letters)
code_to_char = {v: k for k, v in char_to_code.items()}


def encode_string_to_num(input_str):
    """
    Encodes a string to a numeric string using the two-digit code mapping.
    Example: 'abc' -> '101112'
    Assumes all characters are in the mapping; raises ValueError otherwise.
    """
    # Normalize letters to lowercase so encoding is case-insensitive
    result = ''
    for c in input_str:
        key = c.lower() if c.isalpha() else c
        code = char_to_code.get(key)
        if code is None:
            raise ValueError(f"Unknown character '{c}' in input")
        result += f"{code:02d}"
    return result


def decode_num_to_string(num_str):
    """
    Decodes a numeric string back to the original string using the code mapping.
    Example: '101112' -> 'abc'
    Assumes even length and valid codes; raises ValueError otherwise.
    """
    if len(num_str) % 2 != 0:
        raise ValueError("Numeric string must have even length")
    result = ''
    for i in range(0, len(num_str), 2):
        code_str = num_str[i:i+2]
        try:
            code = int(code_str)
        except ValueError:
            raise ValueError(f"Invalid two-digit code '{code_str}' at position {i}")
        c = code_to_char.get(code)
        if c is None:
            raise ValueError(f"Unknown code {code} at position {i}")
        result += c
    return result


def create_savecode(input_list):
    r"""
    Creates a savecode string from a list of fields.
    Escapes '\\' to '\\\\' and '|' to '\\|' in each field.
    Joins with '|' and adds a trailing '|'.
    Example: ['examples', 'galore'] -> 'examples|galore|'
    """
    def escape_field(field):
        # Savecode fields keep their original case; only encoding/decoding of the
        # numeric mapping is case-insensitive. Escape backslashes and pipes.
        return field.replace('\\', '\\\\').replace('|', '\\|')

    escaped_fields = [escape_field(field) for field in input_list]
    return '|'.join(escaped_fields) + '|'


def parse_savecode(input_string):
    r"""
    Parses a savecode string into a list of fields.
    Handles escaping with '\\': '\\\\' -> '\\', '\\|' -> '|', and other escaped chars added literally.
    Assumes the string ends with '|'; splits on unescaped '|'.
    Example: 'example|thingy|' -> ['example', 'thingy']
    Example with escapes: 'this is a normal value|this value needs escaping because of the "\\\|"!|this "\\" also needs escaping|' 
    -> ['this is a normal value', 'this value needs escaping because of the "|"!', 'this "\\" also needs escaping']
    """
    fields = []
    current_field = ''
    i = 0
    length = len(input_string)

    while i < length:
        if input_string[i] == '\\':
            i += 1
            if i < length:
                current_field += input_string[i]  # Add the escaped char literally
            else:
                current_field += '\\'  # Trailing escape (unlikely, but handle)
        elif input_string[i] == '|':
            fields.append(current_field)
            current_field = ''
        else:
            current_field += input_string[i]
        i += 1

    # If no trailing '|', the last field might not be appended, but assume it ends with '|'
    if current_field:
        fields.append(current_field)  # In case no final '|'

    return fields

# cloud engine:
def get_timestamp():
    # Get current time in seconds since epoch
    epoch_time = time.time()
    # Calculate seconds since Jan 1, 2000
    seconds_since_2000 = int(epoch_time - 946684800)
    return seconds_since_2000

def scan_for_requests():
    global requests, cloud
    var1 = get_cloud_var(cloud, "CLOUD_CLIENT_DATA_1")
    var2 = get_cloud_var(cloud, "CLOUD_CLIENT_DATA_2")
    var3 = get_cloud_var(cloud, "CLOUD_CLIENT_DATA_3")
    var4 = get_cloud_var(cloud, "CLOUD_CLIENT_DATA_4")
    
    for idx, clientvar in enumerate([var1, var2, var3, var4], start=1):
        if clientvar and clientvar != "0":
            # Step 1: decode numeric string -> text
            try:
                decoded_str = decode_num_to_string(clientvar)
            except ValueError as ve:
                if debug:
                    print(f"[DEBUG] decode_num_to_string failed for CLOUD_CLIENT_DATA_{idx}: '{clientvar}'")
                    print(f"[DEBUG] ValueError: {ve}")
                    print(traceback.format_exc())
                continue
            except Exception as e:
                if debug:
                    print(f"[DEBUG] Unexpected error during decoding for CLOUD_CLIENT_DATA_{idx}: '{clientvar}'")
                    print(f"[DEBUG] Exception: {e}")
                    print(traceback.format_exc())
                continue

            # Step 2: parse savecode into fields
            try:
                fields = parse_savecode(decoded_str)
            except Exception as e:
                if debug:
                    print(f"[DEBUG] parse_savecode failed for decoded string from CLOUD_CLIENT_DATA_{idx}: '{decoded_str}'")
                    print(f"[DEBUG] Exception: {e}")
                    print(traceback.format_exc())
                continue

            # Validate number of fields
            if len(fields) != 9:
                if debug:
                    print(f"[DEBUG] Invalid number of fields ({len(fields)}) in client variable CLOUD_CLIENT_DATA_{idx}: '{decoded_str}'")
                continue

            # Step 3: convert numeric fields safely (timestamp, lastping)
            try:
                ts = int(fields[4])
            except Exception as e:
                if debug:
                    print(f"[DEBUG] Failed to parse timestamp (field 5) as int for CLOUD_CLIENT_DATA_{idx}: '{fields[4]}'")
                    print(f"[DEBUG] Exception: {e}")
                    print(traceback.format_exc())
                continue

            try:
                lp = int(fields[5])
            except Exception as e:
                if debug:
                    print(f"[DEBUG] Failed to parse lastping (field 6) as int for CLOUD_CLIENT_DATA_{idx}: '{fields[5]}'")
                    print(f"[DEBUG] Exception: {e}")
                    print(traceback.format_exc())
                continue

            # Step 4: construct packet (keep id as string)
            try:
                pkt = packet(
                    sender=fields[0],
                    projectname=fields[1],
                    id=str(fields[2]),
                    timestamp=ts,
                    lastping=lp,
                    parentid=fields[6],
                    payload=fields[7],
                    type=fields[8]
                )
            except Exception as e:
                if debug:
                    print(f"[DEBUG] Failed to construct packet object from fields for CLOUD_CLIENT_DATA_{idx}: {fields!r}")
                    print(f"[DEBUG] Exception: {e}")
                    print(traceback.format_exc())
                continue

            # Step 5: check for duplicates / update existing
            for req in requests:
                if req.id == pkt.id and req.sender == pkt.sender:
                    # Already processing this request, refresh lastping if it is newer
                    try:
                        if pkt.lastping > req.lastping:
                            req.lastping = pkt.lastping
                    except Exception as e:
                        if debug:
                            print(f"[DEBUG] Error updating lastping for request id={pkt.id}, sender={pkt.sender}")
                            print(f"[DEBUG] Exception: {e}")
                            print(traceback.format_exc())
                    break
            else:
                try:
                    if get_timestamp() - pkt.timestamp < 16: # Only accept requests newer than 15 seconds
                        requests.append(pkt)
                        if basicprints:
                            print(f"New request from {pkt.sender}: {pkt.type} (ID: {pkt.id})")
                except Exception as e:
                    if debug:
                        print(f"[DEBUG] Error during timestamp check or appending request for packet id={pkt.id}")
                        print(f"[DEBUG] Exception: {e}")
                        print(traceback.format_exc())
                    continue

def delete_old_requests():
    global requests
    current_time = get_timestamp()
    before_count = len(requests)
    requests = [req for req in requests if current_time - req.lastping < 16]
    after_count = len(requests)
    if basicprints and before_count != after_count:
        print(f"Deleted {before_count - after_count} old requests.")

def process_request(req):
    global requests
    global responsestoping
    resp = response(random.randint(1000000000000000, 9999999999999999), req.id, get_timestamp(), "")
    if req.type == "startup":
        # Startup request: respond with "received"
        resp.payload = "received"
    elif req.type == "helloworld":
        # Hello world request: respond with "Hello, world!"
        resp.payload = "Hello, world!"
    elif req.type == "whois":
        # Whois request: respond with useragent info
        resp.payload = useragent
    elif req.type == "ping":
        # Ping request: respond with "pong"
        resp.payload = "pong"
    elif req.type == "success":
        # successfully recieved response, delete response and set parent request to responded
        responsestoping = [r for r in responsestoping if r.requestid != req.parentid]
        for r in requests:
            if r.id == req.parentid:
                r.state = "responded"
                if basicprints:
                    print(f"Request ID {r.id} from {r.sender} marked as responded.")
            if r.id == req.id:
                r.state = "responded"
    else:
        # Unknown request type: respond with error
        resp.payload = "error: unknown request type"
    if not req.type == "success":
        responsestoping.append(resp)
    
def process_all_requests():
    global requests, responsestoping
    for req in requests:
        if req.state == "new":
            try:
                process_request(req)
                req.state = "pingingresponse"
                if basicprints:
                    print(f"Processed request ID {req.id} from {req.sender}")
            except Exception as e:
                if debug:
                    print(f"[DEBUG] Error processing request ID {req.id} from {req.sender}")
                    print(f"[DEBUG] Exception: {e}")
                    print(traceback.format_exc())
                continue
        
def ping_response():
    global responsestoping, cloud
    # pick random response to ping
    if responsestoping: 
        resp = random.choice(responsestoping)
        response_savecode = create_savecode([
            str(resp.responseid),
            str(resp.requestid),
            str(resp.timestamp),
            str(resp.payload)
        ])
        encoded_response = encode_string_to_num(response_savecode)
        cloud.set_var("CLOUD_SERVER_DATA", encoded_response)
def delete_old_responses():
    # delete responses older than 20 seconds
    global responsestoping
    current_time = get_timestamp()
    before_count = len(responsestoping)
    responsestoping = [r for r in responsestoping if current_time - r.timestamp < 20]
    after_count = len(responsestoping)
    if basicprints and before_count != after_count:
        print(f"Deleted {before_count - after_count} old responses due to timeout.")

while True:
    scan_for_requests()
    delete_old_requests()
    process_all_requests()
    ping_response()
    delete_old_responses()
    time.sleep(0.2)