# scanner.py
#
# This is the brain of the tool.
# It reads a file's raw bytes and figures out what type it really is.
#
# New concept — FUNCTIONS:
# A function is a reusable block of code with a name.
# You define it with "def", then call it by name whenever you need it.
# Example:
#   def greet(name):         ← defines the function
#       print("Hello", name)
#
#   greet("Alice")           ← calls it

import os
import hashlib
import requests

# Pillow — image metadata and EXIF data
try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

# mutagen — audio metadata
try:
    import mutagen
    MUTAGEN_AVAILABLE = True
except ImportError:
    MUTAGEN_AVAILABLE = False

# pymediainfo — video metadata
try:
    from pymediainfo import MediaInfo
    MEDIAINFO_AVAILABLE = True
except ImportError:
    MEDIAINFO_AVAILABLE = False

from magic_db import SIGNATURES, SUSPICIOUS_EXTENSIONS

# ── Detection lists ────────────────────────────────────────────────────────
# These are the software names we check against to identify
# screenshots, screen recordings, and audio recordings.
# All lowercase — we'll lowercase the metadata value before comparing.

SCREENSHOT_SOFTWARE = [
    "gnome-screenshot", "spectacle", "shutter", "scrot",
    "snipping tool", "sharex", "flameshot", "lightshot",
    "greenshot", "obs", "xfce4-screenshooter", "mate-screenshot",
    "screenpresso", "monosnap", "skitch", "gyazo",
]

SCREEN_RECORDER_SOFTWARE = [
    "obs", "obs-studio", "obs studio", "simplescreenrecorder",
    "simple screen recorder", "kazam", "camtasia", "bandicam",
    "ffmpeg", "quicktime", "icecream screen recorder",
    "vokoscreen", "recordmydesktop", "peek", "gifcap",
]

AUDIO_RECORDER_SOFTWARE = [
    "audacity", "arecord", "ffmpeg", "garageband",
    "voice recorder", "soundrecorder", "ocenaudio",
    "ardour", "reaper", "zencastr", "critrole",
]

# Common screen resolutions — used as a clue for screenshot detection
SCREEN_RESOLUTIONS = [
    (1920, 1080), (2560, 1440), (1366, 768), (1280, 720),
    (3840, 2160), (1440, 900), (1280, 800), (1024, 768),
    (1600, 900), (2560, 1600), (1920, 1200), (2880, 1800),
    (1280, 1024), (1360, 768), (1680, 1050), (2048, 1152),
]


def read_header(filepath, num_bytes=32):
    """
    Open a file in BINARY mode and read its first bytes.

    Normally when you open a file, Python reads it as TEXT.
    We need raw bytes instead, so we use "rb" (read binary).

    We only read the first 32 bytes — that's enough for any magic number.
    """
    with open(filepath, "rb") as f:
        return f.read(num_bytes)
    # "with" automatically closes the file when we're done — good habit!


def bytes_to_hex(raw_bytes, limit=16):
    """
    Convert raw bytes into a readable hex string for display.

    Example: b'\\xff\\xd8\\xff' → "FF D8 FF"

    The f"{b:02X}" part means:
      b    = one byte (a number 0-255)
      02   = always show at least 2 digits
      X    = use uppercase hex letters (A-F not a-f)
    """
    return " ".join(f"{b:02X}" for b in raw_bytes[:limit])


def get_extension(filepath):
    """
    Pull the file extension out of a filepath.
    "/home/user/photo.jpg" → "jpg"
    "document"             → "" (empty string, no extension)
    """
    filename = os.path.basename(filepath)   # strips the folder path
    if "." in filename:
        return filename.rsplit(".", 1)[1].lower()
    return ""


def score_signature(header_bytes, magic):
    """
    Score how closely a file's header matches one magic signature.
    Returns a float between 0.0 and 1.0.

    How it works:
      - Loop through each byte in the magic signature
      - Count how many bytes match the file's header at that position
      - Divide matched bytes by total bytes → percentage as a decimal

    Example:
      magic      = [0xFF, 0xD8, 0xFF, 0xE0]   (4 bytes)
      header     = [0xFF, 0xD8, 0xFF, 0x00]   (first 4 bytes of file)
      matches    = 3  (first 3 match, 4th doesn't)
      score      = 3 / 4 = 0.75  (75%)
    """
    if len(header_bytes) < len(magic):
        # File is shorter than the signature — score what we can
        # but apply a penalty since we couldn't check all bytes
        comparable = min(len(header_bytes), len(magic))
    else:
        comparable = len(magic)

    if comparable == 0:
        return 0.0

    matched = sum(
        1 for i in range(comparable)
        if header_bytes[i] == magic[i]
    )

    # Base score = matched bytes / total magic bytes
    base_score = matched / len(magic)

    # Small bonus for longer signatures — a 8-byte match is more
    # meaningful than a 2-byte match at the same percentage
    length_bonus = min(len(magic) / 32, 0.1)   # max 10% bonus

    return min(base_score + length_bonus, 1.0)  # cap at 100%


def match_signature(header_bytes):
    """
    Original behaviour preserved — returns the single best match.
    Used by the rest of scan_file for the primary status decision.

    We keep this separate from probability_matches so the core
    logic doesn't change — we're only ADDING information, not
    replacing the existing decision engine.
    """
    best_match = None
    best_score = 0.0

    for sig in SIGNATURES:
        magic = sig["magic"]
        if len(header_bytes) < 2:
            continue
        # For the primary match we still require a FULL byte match
        # on the first bytes — this keeps false positives low
        magic_length = len(magic)
        if len(header_bytes) >= magic_length:
            if header_bytes[:magic_length] == bytes(magic):
                score = score_signature(header_bytes, magic)
                if score > best_score:
                    best_match = sig
                    best_score = score

    return best_match


def probability_matches(header_bytes, top_n=3, threshold=0.40):
    """
    Return the top N most likely file types with confidence percentages.

    Parameters:
      top_n     — how many results to return (default 3)
      threshold — minimum score to be included (default 40%)
                  anything below this is too uncertain to show

    Returns a list of dicts, each with:
      "label"      — human readable type name
      "ext"        — expected extensions
      "score"      — float 0.0 to 1.0
      "percentage" — integer 0 to 100 (for display)
      "threat"     — whether this type can execute code

    Example return value:
      [
        {"label": "JPEG Image",   "score": 0.98, "percentage": 98, ...},
        {"label": "TIFF Image",   "score": 0.51, "percentage": 51, ...},
        {"label": "Unknown RIFF", "score": 0.42, "percentage": 42, ...},
      ]
    """
    scored = []

    for sig in SIGNATURES:
        score = score_signature(header_bytes, sig["magic"])
        if score >= threshold:
            scored.append({
                "label":      sig["label"],
                "ext":        sig["ext"],
                "score":      score,
                "percentage": round(score * 100),
                "threat":     sig["threat"],
            })

    # Sort highest score first
    scored.sort(key=lambda x: x["score"], reverse=True)

    # Remove duplicates — keep only the highest score per label
    seen = set()
    unique = []
    for item in scored:
        if item["label"] not in seen:
            seen.add(item["label"])
            unique.append(item)

    return unique[:top_n]

def extract_metadata(filepath, detected_type):
    """
    Extract metadata from a file based on its detected type.

    We branch into three paths:
      1. Image  → Pillow reads EXIF + basic image info
      2. Audio  → mutagen reads music/recording tags
      3. Video  → pymediainfo reads stream details

    Returns a dictionary with:
      "fields"  — list of (label, value) pairs to display
      "flag"    — a special notice like "Likely Screenshot" or None
    """

    fields = []   # list of (label, value) tuples
    flag   = None # special detection notice

    dtype = detected_type.lower()

    # ── Branch 1: Images ──────────────────────────────────────────────────
    is_image = any(word in dtype for word in ["image", "jpeg", "png", "gif", "bmp", "webp", "tiff"])

    if is_image and PILLOW_AVAILABLE:
        try:
            img = Image.open(filepath)

            # Basic image info — always available
            fields.append(("Dimensions",  f"{img.width} x {img.height} px"))
            fields.append(("Color mode",  img.mode))
            fields.append(("Format",      img.format or "Unknown"))

            # EXIF data — only present in JPEG and some others
            exif_data = img._getexif() if hasattr(img, "_getexif") else None

            camera_make  = None
            camera_model = None
            date_taken   = None
            software     = None
            gps_lat      = None
            gps_lon      = None

            if exif_data:
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))

                    if tag_name == "Make":
                        camera_make = str(value).strip()
                        fields.append(("Camera make", camera_make))

                    elif tag_name == "Model":
                        camera_model = str(value).strip()
                        fields.append(("Camera model", camera_model))

                    elif tag_name == "DateTime":
                        date_taken = str(value)
                        fields.append(("Date taken", date_taken))

                    elif tag_name == "Software":
                        software = str(value).strip()
                        fields.append(("Software", software))

                    elif tag_name == "XResolution":
                        fields.append(("X resolution", str(value)))

                    elif tag_name == "YResolution":
                        fields.append(("Y resolution", str(value)))

                    elif tag_name == "Flash":
                        fields.append(("Flash", str(value)))

                    elif tag_name == "FocalLength":
                        fields.append(("Focal length", str(value)))

                    elif tag_name == "GPSInfo":
                        # GPSInfo is a nested dictionary
                        # Tag 2 = latitude, Tag 4 = longitude
                        try:
                            lat = value.get(2)
                            lon = value.get(4)
                            if lat and lon:
                                # GPS values come as tuples of fractions
                                # (degrees, minutes, seconds)
                                def to_decimal(coord):
                                    d, m, s = coord
                                    return float(d) + float(m)/60 + float(s)/3600

                                gps_lat = round(to_decimal(lat), 5)
                                gps_lon = round(to_decimal(lon), 5)
                                fields.append(("GPS latitude",  str(gps_lat)))
                                fields.append(("GPS longitude", str(gps_lon)))
                        except Exception:
                            pass

            # ── Screenshot detection ──────────────────────────────────
            # We flag as screenshot if:
            #   - No camera make AND no camera model
            #   - Software matches a known screenshot tool OR
            #     dimensions match a common screen resolution
            no_camera = (camera_make is None and camera_model is None)
            software_lower = software.lower() if software else ""

            software_match = any(
                s in software_lower for s in SCREENSHOT_SOFTWARE
            )
            resolution_match = (img.width, img.height) in SCREEN_RESOLUTIONS

            if no_camera and (software_match or resolution_match):
                reason = []
                if software_match:
                    reason.append(f"software: {software}")
                if resolution_match:
                    reason.append(f"resolution matches screen size")
                flag = f"⚠  Likely Screenshot — {', '.join(reason)}"

        except Exception as e:
            fields.append(("Note", f"Could not read image metadata: {e}"))

    # ── Branch 2: Audio ───────────────────────────────────────────────────
    is_audio = any(word in dtype for word in ["audio", "mp3", "flac", "ogg", "wav", "aac", "midi"])

    if is_audio and MUTAGEN_AVAILABLE:
        try:
            audio = mutagen.File(filepath, easy=True)

            if audio is None:
                fields.append(("Note", "No metadata tags found"))
            else:
                # easy=True gives us clean string keys like "artist", "album"
                tag_map = {
                    "title":        "Title",
                    "artist":       "Artist",
                    "album":        "Album",
                    "date":         "Year",
                    "genre":        "Genre",
                    "tracknumber":  "Track number",
                    "encoder":      "Encoder",
                    "comment":      "Comment",
                }

                found_tags = {}
                for key, label in tag_map.items():
                    val = audio.get(key)
                    if val:
                        # mutagen returns lists — take the first item
                        found_tags[key] = str(val[0])
                        fields.append((label, str(val[0])))

                # Audio stream info
                if hasattr(audio, "info"):
                    info = audio.info
                    if hasattr(info, "length"):
                        secs = int(info.length)
                        fields.append(("Duration", f"{secs//60:02d}:{secs%60:02d}"))
                    if hasattr(info, "channels"):
                        ch = info.channels
                        fields.append(("Channels", f"{ch} ({'Mono' if ch == 1 else 'Stereo'})" ))
                    if hasattr(info, "bitrate"):
                        fields.append(("Bitrate", f"{info.bitrate // 1000} kbps"))
                    if hasattr(info, "sample_rate"):
                        fields.append(("Sample rate", f"{info.sample_rate} Hz"))

                # ── Audio recording detection ─────────────────────────
                # Clues: mono channel, no artist/album/genre,
                # encoder matches recording software
                encoder = found_tags.get("encoder", "").lower()
                has_music_tags = any(
                    k in found_tags for k in ["artist", "album", "genre"]
                )
                is_mono = (
                    hasattr(audio, "info") and
                    hasattr(audio.info, "channels") and
                    audio.info.channels == 1
                )
                encoder_match = any(
                    s in encoder for s in AUDIO_RECORDER_SOFTWARE
                )

                if (is_mono or encoder_match) and not has_music_tags:
                    reason = []
                    if is_mono:
                        reason.append("mono channel")
                    if encoder_match:
                        reason.append(f"encoder: {encoder}")
                    flag = f"⚠  Likely Audio Recording — {', '.join(reason)}"

        except Exception as e:
            fields.append(("Note", f"Could not read audio metadata: {e}"))

    # ── Branch 3: Video ───────────────────────────────────────────────────
    is_video = any(word in dtype for word in ["video", "mp4", "mkv", "webm", "avi", "mov"])

    if is_video and MEDIAINFO_AVAILABLE:
        try:
            media = MediaInfo.parse(filepath)

            encoding_tool = None

            for track in media.tracks:
                # MediaInfo separates data into tracks by type:
                # "General" = overall file info
                # "Video"   = video stream details
                # "Audio"   = audio stream details

                if track.track_type == "General":
                    if track.duration:
                        ms   = int(track.duration)
                        secs = ms // 1000
                        fields.append(("Duration", f"{secs//60:02d}:{secs%60:02d}"))
                    if track.file_size:
                        fields.append(("File size", format_size(int(track.file_size))))
                    if track.encoded_application:
                        encoding_tool = track.encoded_application
                        fields.append(("Encoding tool", encoding_tool))
                    if track.encoded_date:
                        fields.append(("Encoded date", str(track.encoded_date)))
                    if track.writing_library:
                        fields.append(("Writing library", track.writing_library))

                elif track.track_type == "Video":
                    if track.width and track.height:
                        fields.append(("Resolution", f"{track.width} x {track.height}"))
                    if track.frame_rate:
                        fields.append(("Frame rate", f"{track.frame_rate} fps"))
                    if track.format:
                        fields.append(("Video codec", track.format))
                    if track.bit_rate:
                        fields.append(("Video bitrate", f"{int(track.bit_rate)//1000} kbps"))

                elif track.track_type == "Audio":
                    if track.format:
                        fields.append(("Audio codec", track.format))
                    if track.channel_s:
                        fields.append(("Audio channels", str(track.channel_s)))
                    if track.sampling_rate:
                        fields.append(("Sample rate", f"{track.sampling_rate} Hz"))

            # ── Screen recording detection ────────────────────────────
            # Clues: encoding tool matches known screen recorders,
            # no camera metadata, resolution matches screen sizes
            tool_lower = encoding_tool.lower() if encoding_tool else ""
            tool_match = any(
                s in tool_lower for s in SCREEN_RECORDER_SOFTWARE
            )

            # Check resolution from video track
            res_match = False
            for track in media.tracks:
                if track.track_type == "Video":
                    if track.width and track.height:
                        if (int(track.width), int(track.height)) in SCREEN_RESOLUTIONS:
                            res_match = True

            if tool_match or res_match:
                reason = []
                if tool_match:
                    reason.append(f"tool: {encoding_tool}")
                if res_match:
                    reason.append("resolution matches screen size")
                flag = f"⚠  Likely Screen Recording — {', '.join(reason)}"

        except Exception as e:
            fields.append(("Note", f"Could not read video metadata: {e}"))

    return {
        "fields": fields,
        "flag":   flag,
    }


def virustotal_lookup(sha256, api_key):
    """
    Send a SHA-256 hash to VirusTotal and return a verdict.

    api_key is now passed in directly from the app —
    no config.py needed. The GUI handles loading and
    saving the key from settings.json.
    """
    if not api_key or not api_key.strip():
        return {
            "success": False,
            "error":   "no_key",   # special code the GUI checks for
        }

    url     = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key.strip()}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 404:
            return {
                "success": True,
                "found":   False,
                "verdict": "UNKNOWN",
                "error":   "File not found in VirusTotal database. "
                           "Try uploading it manually at virustotal.com",
            }

        if response.status_code == 401:
            return {
                "success": False,
                "error":   "invalid_key",   # special code the GUI checks for
            }

        if response.status_code == 429:
            return {
                "success": False,
                "error":   "Rate limit reached — wait 1 minute and try again.",
            }

        if response.status_code != 200:
            return {
                "success": False,
                "error":   f"VirusTotal returned status {response.status_code}",
            }

        data  = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        total      = malicious + suspicious + undetected + stats.get("harmless", 0)
        detections = malicious + suspicious

        results    = data["data"]["attributes"]["last_analysis_results"]
        flagged_by = [
            engine for engine, result in results.items()
            if result["category"] in ("malicious", "suspicious")
        ]

        if malicious >= 3:
            verdict = "MALICIOUS"
        elif malicious >= 1 or suspicious >= 2:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return {
            "success":    True,
            "found":      True,
            "total":      total,
            "detections": detections,
            "malicious":  malicious,
            "suspicious": suspicious,
            "flagged_by": flagged_by[:10],
            "verdict":    verdict,
            "link":       f"https://www.virustotal.com/gui/file/{sha256}",
            "error":      None,
        }

    except requests.exceptions.ConnectionError:
        return {"success": False, "error": "No internet connection."}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "Request timed out — try again."}
    except Exception as e:
        return {"success": False, "error": f"Unexpected error: {e}"}

   

def calculate_hashes(filepath):
    """
    Read the file in chunks and calculate three hash types.

    Why chunks? Large files (like a 2GB ISO) would crash your
    program if you tried to load them fully into memory at once.
    Reading in 65536-byte chunks keeps memory usage flat no matter
    how big the file is.

    MD5    — fast, 32-char hex. Widely used but not collision-proof.
              Still the most common hash you'll see on VirusTotal.
    SHA-1  — 40-char hex. Stronger than MD5, also widely supported.
    SHA-256 — 64-char hex. The current gold standard for integrity.
    """
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()

    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):   # read 64KB at a time
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        return {
            "md5":    md5.hexdigest(),      # hexdigest() gives the final hex string
            "sha1":   sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }

    except (PermissionError, OSError):
        return {
            "md5":    "unavailable",
            "sha1":   "unavailable",
            "sha256": "unavailable",
        }



def format_size(num_bytes):
    """Turn a raw byte count into a readable string."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    elif num_bytes < 1024 ** 2:
        return f"{num_bytes / 1024:.1f} KB"
    else:
        return f"{num_bytes / 1024 ** 2:.2f} MB"


def scan_file(filepath):
    """
    The main function. Scans one file and returns a report as a dictionary.

    A dictionary in Python stores key-value pairs, like a real dictionary:
      {"filename": "photo.jpg", "status": "CLEAN", ...}
    You access values with: result["filename"]
    """

    # ── 1. Try to read the file ──────────────────────────────────────────
    try:
        header = read_header(filepath)
    except FileNotFoundError:
        return {"error": f"File not found: {filepath}"}
    except PermissionError:
        return {"error": f"Permission denied: {filepath}"}

    # ── 2. Collect basic info ────────────────────────────────────────────
    file_size = os.path.getsize(filepath)
    extension = get_extension(filepath)
    filename  = os.path.basename(filepath)
    hex_header = bytes_to_hex(header)

    # ── 3. Match against our database ───────────────────────────────────
    match = match_signature(header)

    # ── 4. Decide the status ─────────────────────────────────────────────
    #
    # We use a list to collect findings (there could be more than one).
    # "findings" are the human-readable explanations of what we detected.

    status   = "CLEAN"
    findings = []

    if match is None:
        # No magic number matched at all
        status = "UNKNOWN"
        findings.append(
            "No known magic signature found. "
            "File type could not be verified from its bytes."
        )

    else:
        # A match was found — now check if the extension fits
        ext_ok = (extension in match["ext"]) or (extension == "")

        if not ext_ok:
            # The file claims to be one thing but its bytes say another
            status = "MISMATCH"
            findings.append(
                f'Extension ".{extension}" does not match the detected file type.\n'
                f'    Detected type : {match["label"]}\n'
                f'    Expected ext  : {", ".join(match["ext"])}'
            )

        if match["threat"]:
            # The magic number belongs to an executable type
            status = "THREAT"
            findings.append(
                f'Executable signature detected: {match["label"]}.\n'
                f'    This file type can run code on a computer.'
            )

    # Extension-only warning (even if magic was unknown)
    if extension in SUSPICIOUS_EXTENSIONS and status == "CLEAN":
        status = "WARNING"
        findings.append(
            f'Extension ".{extension}" is commonly used to deliver malware.'
        )

    # Empty file
    if file_size == 0:
        status = "WARNING"
        findings.append("File is empty (0 bytes).")

    # ── 5. Return the full report ─────────────────────────────────────────

    hashes = calculate_hashes(filepath)
    probabilities = probability_matches(header)
    metadata = extract_metadata(filepath, match["label"] if match else "")
    return {
        "filename":      filename,
        "filepath":      filepath,
        "file_size":     file_size,
        "size_readable": format_size(file_size),
        "extension":     extension,
        "hex_header":    hex_header,
        "detected_type": match["label"] if match else "Unknown",
        "status":        status,
        "findings":      findings,
        "md5":           hashes["md5"],
        "sha1":          hashes["sha1"],
        "sha256":        hashes["sha256"],
        "probabilities": probabilities,
        "metadata":      metadata,      
    }
