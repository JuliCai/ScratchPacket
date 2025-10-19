import os
import scratchattach as sa
from scratchpacket import Packet, Response, Save
import time
import traceback
import random
from openai import OpenAI
import threading
import base64
import io
import re
import string
from PIL import Image
from datetime import datetime

"""
CHANGE THESE VARIABLES:
"""

runtime = 595  # Set the runtime duration in seconds that the server should run before shutting down
project_id = "1230640342"  # Replace with your Scratch project ID
logfile_path = "logs.log"  # Path to your log file
useragent = "library: scratchpacket/1.0 by jhalloran | cloud bot by YOUR NAME"  # User agent for Scratch requests
debug = True  # Whether to print debug stuff (not recommended outside development)
basicprints = True  # Whether to print basic status/lifecycle updates (recommended for running locally, not recommended for servers)
deepdebug = False  # Whether to print very verbose debug info (not recommended outside development)
MAX_WORKERS = 4  # Max number of requests to process concurrently (>=2 recommended to handle verify while genai runs)

# Directory to store generated images (created if missing)
images_dir = "generated_images"

# Deep-debug controls
TRUNCATE_AT = 2000  # Max characters to print for raw payloads (set higher/lower as needed)
SHOW_SYSTEM_PROMPT_IN_DEEPDEBUG = True  # If False, deepdebug will only print the system prompt length instead of contents

"""
DON'T CHANGE THESE VARIABLES:
"""
saves = []
requests = []
responsestoping = []
cloud = sa.get_tw_cloud(project_id, purpose=useragent)
savefilepath = "saves.save"
client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)

# Concurrency primitives
requests_lock = threading.RLock()
responsestoping_lock = threading.RLock()
saves_lock = threading.RLock()
stop_event = threading.Event()
processing_semaphore = threading.Semaphore(MAX_WORKERS)

# In-memory image cache: { server_filename: {"path": <png path>, "hsv": <hsv string>, "created": <ts>} }
image_cache = {}
image_cache_lock = threading.RLock()

# Metrics store keyed by (sender, id)
metrics_lock = threading.RLock()
request_metrics = {}  # {(sender, id): {"arrival": t, "claimed": t, "start": t, "end": t, ...}}

# Track last-seen client cloud vars by name to avoid spammy logs
last_seen_client_vars = {
    "CLOUD_CLIENT_DATA_1": None,
    "CLOUD_CLIENT_DATA_2": None,
    "CLOUD_CLIENT_DATA_3": None,
    "CLOUD_CLIENT_DATA_4": None,
}

# Ensure images directory exists
os.makedirs(images_dir, exist_ok=True)

# -----------------
# Logging helpers
# -----------------
log_lock = threading.RLock()
_log_file_handle = None

def _now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"

def _truncate(s, n=TRUNCATE_AT):
    if s is None:
        return "None"
    if n is None:
        return str(s)
    s = str(s)
    return s if len(s) <= n else (s[:n] + f"... [truncated {len(s)-n} chars]")

def _open_log():
    global _log_file_handle
    if _log_file_handle is None:
        _log_file_handle = open(logfile_path, "a", encoding="utf-8", buffering=1)
        header = f"{_now()} [INIT] logfile opened; deepdebug={deepdebug}, debug={debug}, basicprints={basicprints}, MAX_WORKERS={MAX_WORKERS}\n"
        _log_file_handle.write(header)

def _should_emit(level):
    # BASIC respects basicprints; DEBUG respects debug or deepdebug; DEEP respects deepdebug
    if level == "BASIC":
        return basicprints
    if level == "DEBUG":
        return debug or deepdebug
    if level == "DEEP":
        return deepdebug
    return True

def _log(level, msg):
    if not _should_emit(level):
        return
    line = f"{_now()} [{level}] [T{threading.get_ident()}] {msg}\n"
    with log_lock:
        _open_log()
        # Console
        print(line, end="")
        # File
        try:
            _log_file_handle.write(line)
        except Exception:
            # Best-effort: do not crash on logging errors
            pass

def log_basic(msg): _log("BASIC", msg)
def log_debug(msg): _log("DEBUG", msg)
def log_deep(msg): _log("DEEP", msg)

def _metrics_key(req):
    return (getattr(req, "sender", "unknown"), str(getattr(req, "id", "unknown")))

def _get_metrics(req, create=True):
    key = _metrics_key(req)
    with metrics_lock:
        m = request_metrics.get(key)
        if m is None and create:
            m = {}
            request_metrics[key] = m
        return m

def _format_packet(req):
    return f"Packet(sender={req.sender}, projectname={req.projectname}, id={req.id}, ts={req.timestamp}, lastping={req.lastping}, parentid={req.parentid}, type={req.type}, payload={_truncate(req.payload)})"

def _format_response(resp):
    return f"Response(responseid={resp.responseid}, requestid={resp.requestid}, timestamp={resp.timestamp}, payload_len={len(str(resp.payload))}, payload_sample={_truncate(resp.payload)})"

def _format_queue_snapshot():
    with requests_lock:
        states = {}
        for r in requests:
            states[r.state] = states.get(r.state, 0) + 1
        total = len(requests)
    with responsestoping_lock:
        outq = len(responsestoping)
    return f"queue_snapshot total_in={total}, states={states}, pending_out={outq}"

system_prompt_content = """
# BRIEF:
you are a highly intelligent AI assistant named ScratchGPT, developed by the scratch user JuliCai.

# RESPONSE STYLE:
- Respond relatively concisely, with a response length up to 6 sentences.
- Markdown and other formatting (LaTeX, etc.) is NOT supported.
- Please be aware that only charachters in the standard qwerty keyboard layout are supported. "—", for example, is not supported. All non-supported charachters will not be included in the user-facing response.
- newline characters are not supported.

# GENERATING IMAGES:
- you can generate images
- To generate an image, respond STRICTLY with the following format:
`_-GENERATE-IMAGE-_|{{prompt text here}}|_-GENERATE-IMAGE-_|`
- Replace {{prompt text here}} with the actual prompt for the image generation.
- Do not include any other text, formatting, or characters in your response.
- the "`" characters are not part of the response, they are just to indicate the format here.
- the "|" at the very end is required.

# STRICT CONTENT GUIDELINES:
DO NOT respond with anything that could be age-inappropriate or violate scratch community guidelines.
"""

def save_saves_to_file():
    with saves_lock:
        with open(savefilepath, "w", encoding="utf-8") as f:
            for save in saves:
                savecode = create_savecode([
                    str(save.username).lower(),
                    str(save.data),
                    str(save.lastsaved),
                    str(save.firstsaved)
                ])
                f.write(savecode + "\n")
    log_basic("Saves flushed to disk.")

def load_saves_from_file():
    global saves
    with saves_lock:
        saves = []
        if not os.path.exists(savefilepath):
            return
        with open(savefilepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                fields = parse_savecode(line)
                if len(fields) != 4:
                    continue
                try:
                    save = Save(
                        username=fields[0],
                        data=fields[1],
                        lastsaved=int(fields[2]),
                        firstsaved=int(fields[3])
                    )
                    saves.append(save)
                except Exception as e:
                    if debug:
                        log_debug(f"Error loading save from line: {line}")
                        log_debug(f"Exception: {e}")
                        log_debug(traceback.format_exc())
    log_basic(f"Loaded {len(saves)} saves from disk.")

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
        val = all_vars.get(var_name, None)
        # Deepdebug: show raw cloud var when it changes
        if deepdebug:
            prev = last_seen_client_vars.get(var_name)
            if val != prev and val not in (None, "0", ""):
                last_seen_client_vars[var_name] = val
                log_deep(f"cloud_var_changed {var_name}={_truncate(val)} (len={0 if val is None else len(str(val))})")
        return val
    except Exception as e:
        log_basic(f"Error fetching all cloud variables: {e}")
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
    Skips any character not in the mapping (no exception).
    An exception is "—", which is mapped to '-' (51).
    """
    result = ''
    for c in input_str:
        key = c.lower() if c.isalpha() else c
        code = char_to_code.get(key)
        if code is None and c == '—':  # Special case for em dash
            code = char_to_code['-']
        if code is None:
            if debug:
                log_debug(f"Skipping unknown character during encoding: {repr(c)}")
            continue
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
                current_field += input_string[i]
            else:
                current_field += '\\'
        elif input_string[i] == '|':
            fields.append(current_field)
            current_field = ''
        else:
            current_field += input_string[i]
        i += 1

    if current_field:
        fields.append(current_field)

    return fields

# --- Image helpers ---

def random_alnum(n=10):
    """Return a lowercase alphanumeric string of length n."""
    alphabet = string.ascii_lowercase + string.digits
    return ''.join(random.choice(alphabet) for _ in range(n))

def image_to_hsv_string(filepath):
    """
    Loads a PNG image, converts it to a 90x90 HSV representation, and returns it as a string.
    Each pixel is H,S,V scaled to 0-99 and encoded as six chars: HHSSVV.
    """
    try:
        from PIL import Image as _Image  # local alias to ensure availability
        with _Image.open(filepath) as img:
            img = img.convert("RGB")
            resized_img = img.resize((90, 90), _Image.NEAREST)
            hsv_img = resized_img.convert("HSV")

            hsv_string = []
            width, height = hsv_img.size
            for y in range(height):
                for x in range(width):
                    h, s, v = hsv_img.getpixel((x, y))
                    h_scaled = int((h / 255) * 99)
                    s_scaled = int((s / 255) * 99)
                    v_scaled = int((v / 255) * 99)
                    hsv_string.append(f"{h_scaled:02d}{s_scaled:02d}{v_scaled:02d}")

            return "".join(hsv_string)
    except Exception as e:
        if debug:
            log_debug(f"image_to_hsv_string error for '{filepath}': {e}")
            log_debug(traceback.format_exc())
        return None

def generate_90x90_image_with_openai(prompt):
    """
    Uses OpenAI Images API to generate an image for the prompt, resizes to 90x90 RGB PNG,
    saves to disk under generated_images/scratchgpt_image_{10}.png, precomputes HSV string,
    and returns (server_filename, png_path, hsv_string).
    """
    t0 = time.perf_counter()
    # 1) Call OpenAI Images API at a larger size, then downscale to 90x90
    result = client.images.generate(
        model="gpt-image-1-mini",
        prompt=prompt,
        size="1024x1024",  # generate larger, then resize for better quality
        quality="low" # faster and cheaper, not noticable at 90x90
    )
    t1 = time.perf_counter()
    b64 = None
    try:
        b64 = result.data[0].b64_json
    except Exception:
        pass
    if not b64:
        raise RuntimeError("OpenAI returned no image data")

    # 2) Decode and load as PIL Image, convert and resize
    raw = base64.b64decode(b64)
    img = Image.open(io.BytesIO(raw)).convert("RGB")
    img90 = img.resize((90, 90), Image.NEAREST)

    # 3) Create server filename and save PNG
    server_filename = f"scratchgpt_image_{random_alnum(10)}"
    png_path = os.path.join(images_dir, server_filename + ".png")
    img90.save(png_path, format="PNG")

    # 4) Precompute HSV string for fast retrieval
    hsv_str = image_to_hsv_string(png_path)
    if hsv_str is None:
        raise RuntimeError("Failed to compute HSV string for generated image")

    # 5) Cache metadata
    with image_cache_lock:
        image_cache[server_filename] = {
            "path": png_path,
            "hsv": hsv_str,
            "created": int(time.time()),
        }

    t2 = time.perf_counter()
    if deepdebug:
        log_deep(f"genai-image openai_time_ms={(t1-t0)*1000:.1f}, postproc_time_ms={(t2-t1)*1000:.1f}, prompt={_truncate(prompt)}, b64_len={len(b64)}, saved_path={png_path}")
    return server_filename, png_path, hsv_str

def get_hsv_by_server_filename(server_filename):
    """
    Validates and returns the HSV string for server_filename.
    If cached, returns from cache; else tries to load from disk and compute.
    """
    # allow only exact pattern: scratchgpt_image_{10 lowercase alnum}
    if not re.fullmatch(r"scratchgpt_image_[a-z0-9]{10}", server_filename):
        return None, "error: invalid filename"

    with image_cache_lock:
        entry = image_cache.get(server_filename)

    if entry and entry.get("hsv"):
        return entry["hsv"], None

    # Not cached (or missing), try to compute from disk
    png_path = os.path.join(images_dir, server_filename + ".png")
    if not os.path.exists(png_path):
        return None, "error: not found"

    hsv = image_to_hsv_string(png_path)
    if hsv is None:
        return None, "error: failed to compute hsv"

    with image_cache_lock:
        image_cache[server_filename] = {
            "path": png_path,
            "hsv": hsv,
            "created": int(time.time()),
        }
    return hsv, None

# cloud engine:
def get_timestamp():
    epoch_time = time.time()
    seconds_since_2000 = int(epoch_time - 946684800)
    return seconds_since_2000

def scan_for_requests():
    t0 = time.perf_counter()
    global requests, cloud
    var1 = get_cloud_var(cloud, "CLOUD_CLIENT_DATA_1")
    var2 = get_cloud_var(cloud, "CLOUD_CLIENT_DATA_2")
    var3 = get_cloud_var(cloud, "CLOUD_CLIENT_DATA_3")
    var4 = get_cloud_var(cloud, "CLOUD_CLIENT_DATA_4")
    for idx, clientvar in enumerate([var1, var2, var3, var4], start=1):
        if clientvar and clientvar != "0":
            if deepdebug:
                log_deep(f"scan_for_requests raw_numeric CLOUD_CLIENT_DATA_{idx} len={len(clientvar)} sample={_truncate(clientvar)}")
            # Step 1: decode numeric string -> text
            try:
                decoded_str = decode_num_to_string(clientvar)
                if deepdebug:
                    log_deep(f"decoded CLOUD_CLIENT_DATA_{idx}={_truncate(decoded_str)}")
            except ValueError as ve:
                if debug:
                    log_debug(f"decode_num_to_string failed for CLOUD_CLIENT_DATA_{idx}: '{_truncate(clientvar)}'")
                    log_debug(f"ValueError: {ve}")
                    log_debug(traceback.format_exc())
                continue
            except Exception as e:
                if debug:
                    log_debug(f"Unexpected error during decoding for CLOUD_CLIENT_DATA_{idx}: '{_truncate(clientvar)}'")
                    log_debug(f"Exception: {e}")
                    log_debug(traceback.format_exc())
                continue

            # Step 2: parse savecode into fields
            try:
                fields = parse_savecode(decoded_str)
                if deepdebug:
                    log_deep(f"parsed_fields_{idx} count={len(fields)} fields={_truncate(fields)}")
            except Exception as e:
                if debug:
                    log_debug(f"parse_savecode failed for decoded string from CLOUD_CLIENT_DATA_{idx}: '{_truncate(decoded_str)}'")
                    log_debug(f"Exception: {e}")
                    log_debug(traceback.format_exc())
                continue

            # Validate number of fields
            if len(fields) != 9:
                if debug:
                    log_debug(f"Invalid number of fields ({len(fields)}) in client variable CLOUD_CLIENT_DATA_{idx}: '{_truncate(decoded_str)}'")
                continue

            # Step 3: convert numeric fields safely (timestamp, lastping)
            try:
                ts = int(fields[4])
            except Exception as e:
                if debug:
                    log_debug(f"Failed to parse timestamp (field 5) as int for CLOUD_CLIENT_DATA_{idx}: '{fields[4]}'")
                    log_debug(f"Exception: {e}")
                    log_debug(traceback.format_exc())
                continue

            try:
                lp = int(fields[5])
            except Exception as e:
                if debug:
                    log_debug(f"Failed to parse lastping (field 6) as int for CLOUD_CLIENT_DATA_{idx}: '{fields[5]}'")
                    log_debug(f"Exception: {e}")
                    log_debug(traceback.format_exc())
                continue

            # Step 4: construct packet (keep id as string)
            try:
                pkt = Packet(
                    sender=fields[0],
                    projectname=fields[1],
                    id=str(fields[2]),
                    timestamp=ts,
                    lastping=lp,
                    parentid=fields[6],
                    payload=fields[7],
                    type=fields[8]
                )
                if deepdebug:
                    log_deep(f"constructed { _format_packet(pkt) }")
            except Exception as e:
                if debug:
                    log_debug(f"Failed to construct packet object from fields for CLOUD_CLIENT_DATA_{idx}: {fields!r}")
                    log_debug(f"Exception: {e}")
                    log_debug(traceback.format_exc())
                continue

            # Step 5: check for duplicates / update existing
            try:
                now_ts = get_timestamp()
                with requests_lock:
                    for req in requests:
                        if req.id == pkt.id and req.sender == pkt.sender:
                            # Already processing this request, refresh lastping if it is newer
                            if pkt.lastping > req.lastping:
                                req.lastping = pkt.lastping
                            break
                    else:
                        # Only accept requests newer than 15 seconds
                        if now_ts - pkt.timestamp < 16:
                            requests.append(pkt)
                            # record arrival metrics
                            m = _get_metrics(pkt, create=True)
                            m["arrival"] = time.perf_counter()
                            m["client_ts"] = pkt.timestamp
                            if basicprints:
                                log_basic(f"New request from {pkt.sender}: {pkt.type} (ID: {pkt.id})")
                            if deepdebug:
                                log_deep(_format_queue_snapshot())
            except Exception as e:
                if debug:
                    log_debug(f"Error during timestamp check or appending request for packet id={pkt.id}")
                    log_debug(f"Exception: {e}")
                    log_debug(traceback.format_exc())
                continue
    if deepdebug:
        log_deep(f"scan_for_requests_loop_time_ms={(time.perf_counter()-t0)*1000:.1f}")

def delete_old_requests():
    global requests
    current_time = get_timestamp()
    with requests_lock:
        before = list(requests)
        requests = [req for req in requests if current_time - req.lastping < 16]
        removed = [r for r in before if r not in requests]
    if basicprints and removed:
        log_basic(f"Deleted {len(removed)} old requests.")
    if deepdebug and removed:
        ids = [(r.sender, r.id, r.type) for r in removed]
        log_deep(f"delete_old_requests removed={ids}")

def process_request(req):
    global requests
    global responsestoping
    m = _get_metrics(req, create=True)
    start = time.perf_counter()
    resp = Response(random.randint(1000000000000000, 9999999999999999), req.id, get_timestamp(), "")
    if deepdebug:
        log_deep(f"process_request start { _format_packet(req) }")

    if req.type == "startup":
        resp.payload = "received"

    elif req.type == "helloworld":
        resp.payload = "Hello, world!"

    elif req.type == "whois":
        resp.payload = useragent

    elif req.type == "ping":
        resp.payload = "pong"

    elif req.type == "genai":
        # GenAI request: use openai api to generate response based on prompt in payload
        openai_t0 = time.perf_counter()
        if deepdebug:
            if SHOW_SYSTEM_PROMPT_IN_DEEPDEBUG:
                sp_preview = _truncate(system_prompt_content)
            else:
                sp_preview = f"[hidden; len={len(system_prompt_content)}]"
            log_deep(f"genai_request model=gpt-5 reasoning=low system={sp_preview} user={_truncate(req.payload)}")
        response = client.responses.create(
            model="gpt-5",
            reasoning={"effort": "low"},
            input=[
                {"role": "system", "content": system_prompt_content},
                {"role": "user", "content": req.payload}
            ]
        )
        openai_t1 = time.perf_counter()
        # Attempt to extract text safely
        out_text = ""
        try:
            out_text = response.output_text
        except Exception:
            # Fallback: stringify response object
            out_text = str(response)
        resp.payload = out_text
        m["genai_openai_ms"] = (openai_t1 - openai_t0) * 1000.0
        if deepdebug:
            log_deep(f"genai_response time_ms={m['genai_openai_ms']:.1f} out_len={len(str(out_text))} out_sample={_truncate(out_text)}")

    elif req.type == "genai-image":
        # Generate image via OpenAI, store on disk, reply with server filename
        try:
            if deepdebug:
                log_deep(f"genai-image request prompt={_truncate(req.payload)}")
            server_filename, png_path, _hsv = generate_90x90_image_with_openai(req.payload)
            resp.payload = server_filename  # IMPORTANT: only the name, no extension
            if debug:
                log_debug(f"genai-image OK: {server_filename} -> {png_path}")
        except Exception as e:
            if debug:
                log_debug(f"genai-image failed: {e}")
                log_debug(traceback.format_exc())
            resp.payload = "error: genai-image failed"

    elif req.type == "getimage":
        # Retrieve full HSV string for a previously generated image (by server filename)
        filename = str(req.payload).strip()
        hsv, err = get_hsv_by_server_filename(filename)
        if err:
            resp.payload = err  # e.g., "error: not found" or "error: invalid filename"
            if debug:
                log_debug(f"getimage error for '{filename}': {err}")
        else:
            resp.payload = hsv
            if debug:
                log_debug(f"getimage OK for '{filename}', len={len(hsv)}")

    elif req.type == "success":
        # successfully received response, delete response and set parent request to responded
        try:
            with responsestoping_lock:
                responsestoping = [r for r in responsestoping if r.requestid != req.parentid]
            with requests_lock:
                for r in requests:
                    if r.id == req.parentid:
                        r.state = "responded"
                        if basicprints:
                            log_basic(f"Request ID {r.id} from {r.sender} marked as responded.")
                    if r.id == req.id:
                        r.state = "responded"
        except Exception as e:
            if debug:
                log_debug(f"Error marking request success for parentid={req.parentid}, id={req.id}")
                log_debug(f"Exception: {e}")
                log_debug(traceback.format_exc())

    elif req.type == "load":
        # load request. Search for save by username and respond with data. If no save found, respond with blank payload.
        found_save = None
        with saves_lock:
            for save in saves:
                if save.username == req.payload:
                    found_save = save
                    break
        if found_save:
            resp.payload = found_save.data
        else:
            resp.payload = ""
        if debug:
            if found_save:
                log_debug(f"Processed load request ID {req.id} from {req.sender}, found save for username '{req.payload}'")
            else:
                log_debug(f"Processed load request ID {req.id} from {req.sender}, no save found for username '{req.payload}'")

    elif req.type == "save":
        # save request. Save data for username in payload. If save exists, update it. If not, create new save.
        fields = parse_savecode(req.payload)
        if len(fields) != 2:
            resp.payload = "error: invalid save format"
        else:
            username = fields[0]
            data = fields[1]
            with saves_lock:
                existing_save = None
                for save in saves:
                    if save.username == username:
                        existing_save = save
                        break
                current_time = get_timestamp()
                if existing_save:
                    existing_save.data = data
                    existing_save.lastsaved = current_time
                    resp.payload = "updated"
                    if debug:
                        log_debug(f"Updated existing save for username '{username}' from request ID {req.id} by {req.sender}")
                else:
                    new_save = Save(username, data, current_time, current_time)
                    saves.append(new_save)
                    resp.payload = "created"
                    if debug:
                        log_debug(f"Created new save for username '{username}' from request ID {req.id} by {req.sender}")
        if deepdebug:
            log_deep(f"save_request username={_truncate(fields[0] if len(fields) > 0 else '')} data_sample={_truncate(fields[1] if len(fields) > 1 else '')}")

    elif req.type == "verify":
        # verify request. Search for verification code in comments of the authenticator project, and respond with the username who sent it. If no comment found, respond with a blank payload.
        authenticator_project_id = 1230277868
        auth_project = sa.get_project(str(authenticator_project_id))
        auth_comments = auth_project.comments(limit=100, offset=0)
        if debug:
            log_debug(req.payload)
        for comment in auth_comments:
            if debug and deepdebug:
                log_deep(f"verify_scan comment_by={comment.author_name} content={_truncate(comment.content.strip())}")
            if comment.content.strip() == req.payload.strip():
                if debug:
                    log_debug(f"Found matching verification code in comment by user: {comment.author_name}, code: '{comment.content.strip()}'")
                resp.payload = comment.author_name
                break
        if debug:
            log_debug(f"Processed verify request ID {req.id} from {req.sender}, responded with username: '{resp.payload}'")

    else:
        # Unknown request type: respond with error
        resp.payload = "error: unknown request type"

    # Add response to outgoing list (except for "success" control packets)
    if not req.type == "success":
        with responsestoping_lock:
            responsestoping.append(resp)
        if deepdebug:
            log_deep(f"queued_response {_format_response(resp)}; {_format_queue_snapshot()}")

    end = time.perf_counter()
    m["process_ms"] = (end - start) * 1000.0
    if deepdebug:
        # Per-request timing summary
        claimed = m.get("claimed")
        arrival = m.get("arrival")
        waits = ""
        if arrival is not None and claimed is not None:
            waits = f", queue_wait_ms={(claimed - arrival)*1000:.1f}"
        log_deep(f"process_request end id={req.id} type={req.type} process_ms={m['process_ms']:.1f}{waits}")

def _process_one_request_worker(req):
    """
    Worker that processes a single request, then marks it as ready to ping.
    Uses a semaphore to limit concurrency.
    """
    m = _get_metrics(req, create=True)
    m["start"] = time.perf_counter()
    try:
        process_request(req)
        with requests_lock:
            # Move to next lifecycle state; ping_response will handle broadcasting
            req.state = "pingingresponse"
        if basicprints:
            log_basic(f"Processed request ID {req.id} from {req.sender}")
    except Exception as e:
        if debug:
            log_debug(f"Error processing request ID {req.id} from {req.sender}")
            log_debug(f"Exception: {e}")
            log_debug(traceback.format_exc())
    finally:
        m["end"] = time.perf_counter()
        if deepdebug:
            total_ms = (m["end"] - m["start"]) * 1000.0
            log_deep(f"worker_timing id={req.id} total_ms={total_ms:.1f}")
        processing_semaphore.release()

def process_all_requests():
    """
    Background dispatcher that continuously picks up NEW requests and processes
    them in parallel, up to MAX_WORKERS at a time.
    """
    while not stop_event.is_set():
        to_process = []
        with requests_lock:
            for req in requests:
                if req.state == "new":
                    req.state = "processing"
                    to_process.append(req)
                    # record claim time
                    m = _get_metrics(req, create=True)
                    m["claimed"] = time.perf_counter()
        # Spawn worker threads for the newly claimed requests
        for req in to_process:
            processing_semaphore.acquire()
            t = threading.Thread(target=_process_one_request_worker, args=(req,), daemon=True)
            if deepdebug:
                log_deep(f"spawn_worker id={req.id} type={req.type}")
            t.start()
        time.sleep(0.02)  # Small delay to avoid busy-spinning

def ping_response():
    global responsestoping, cloud
    # Pick a random response to ping (if any)
    t0 = time.perf_counter()
    encoded_response = None
    resp = None
    with responsestoping_lock:
        if responsestoping:
            resp = random.choice(responsestoping)
            response_savecode = create_savecode([
                str(resp.responseid),
                str(resp.requestid),
                str(resp.timestamp),
                str(resp.payload)
            ])
            if deepdebug:
                log_deep(f"ping_response raw_savecode={_truncate(response_savecode)}")
            encoded_response = encode_string_to_num(response_savecode)
    if encoded_response is not None:
        cloud.set_var("CLOUD_SERVER_DATA", encoded_response)
        if deepdebug:
            log_deep(f"ping_response set_var len={len(encoded_response)} took_ms={(time.perf_counter()-t0)*1000:.1f} for requestid={resp.requestid if resp else 'n/a'}")

def delete_old_responses():
    # delete responses older than 20 seconds
    global responsestoping
    current_time = get_timestamp()
    with responsestoping_lock:
        before = list(responsestoping)
        responsestoping = [r for r in responsestoping if current_time - r.timestamp < 20]
        removed = [r for r in before if r not in responsestoping]
    if basicprints and removed:
        log_basic(f"Deleted {len(removed)} old responses due to timeout.")
    if deepdebug and removed:
        ids = [(r.requestid, r.responseid) for r in removed]
        log_deep(f"delete_old_responses removed={ids}")

# Startup: load saves, launch background processing thread, then run cloud loop
load_saves_from_file()
processor_thread = threading.Thread(target=process_all_requests, name="RequestProcessor", daemon=True)
processor_thread.start()
log_basic("Background RequestProcessor started.")

starttime = time.time()
if deepdebug:
    log_deep("Server main loop entered.")

try:
    while time.time() - starttime < runtime:
        scan_for_requests()
        delete_old_requests()
        # process_all_requests()  # moved to background thread
        ping_response()
        delete_old_responses()
        time.sleep(0.2)
except KeyboardInterrupt:
    log_basic("KeyboardInterrupt received, shutting down early.")

# Shutdown
if basicprints:
    log_basic("Runtime limit reached, shutting down.")
stop_event.set()
# Give the processor thread a brief moment to exit its loop
processor_thread.join(timeout=2.0)

save_saves_to_file()
cloud.disconnect()
try:
    if _log_file_handle:
        _log_file_handle.flush()
except Exception:
    pass
os._exit(0)  # required because scratchattach's event threads don't shut off even if you tell them to