# magic_db.py
#
# This file is our database of magic numbers.
# Each entry is a Python "dictionary" (a collection of labeled values).
# It describes one file type with 4 pieces of info:
#
#   "label"  → human-readable name shown in results
#   "magic"  → the expected bytes at the start of the file
#   "ext"    → file extensions this type normally uses
#   "threat" → True if this file can execute code (dangerous)
#
# What is 0xFF? It's a "hexadecimal" number.
# Computers store data as bytes (0-255). Hex is just a shorthand:
#   0xFF = 255, 0x4D = 77, 0x5A = 90
# Analysts always write bytes in hex because it's compact and standard.

SIGNATURES = [

    # ── Images ──────────────────────────────────────────────────────────
    {
        "label": "JPEG Image",
        "magic": [0xFF, 0xD8, 0xFF],
        "ext":   ["jpg", "jpeg"],
        "threat": False,
    },
    {
        "label": "PNG Image",
        "magic": [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        "ext":   ["png"],
        "threat": False,
    },
    {
        "label": "GIF Image",
        "magic": [0x47, 0x49, 0x46, 0x38],   # spells "GIF8" in ASCII
        "ext":   ["gif"],
        "threat": False,
    },
    {
        "label": "BMP Image",
        "magic": [0x42, 0x4D],               # spells "BM"
        "ext":   ["bmp"],
        "threat": False,
    },
    {
        "label": "WebP Image",
        "magic": [0x52, 0x49, 0x46, 0x46],   # spells "RIFF"
        "ext":   ["webp"],
        "threat": False,
    },

    # ── Documents ────────────────────────────────────────────────────────
    {
        "label": "PDF Document",
        "magic": [0x25, 0x50, 0x44, 0x46],   # spells "%PDF"
        "ext":   ["pdf"],
        "threat": False,
    },
    {
        "label": "MS Office modern (Word / Excel / PowerPoint)",
        "magic": [0x50, 0x4B, 0x03, 0x04],   # spells "PK" — they're ZIP files inside!
        "ext":   ["docx", "xlsx", "pptx"],
        "threat": False,
    },
    {
        "label": "MS Office legacy (Word / Excel old format)",
        "magic": [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
        "ext":   ["doc", "xls", "ppt"],
        "threat": False,
    },
    {
        "label": "Rich Text Format",
        "magic": [0x7B, 0x5C, 0x72, 0x74, 0x66],  # spells "{\rtf"
        "ext":   ["rtf"],
        "threat": False,
    },

    # ── Archives ─────────────────────────────────────────────────────────
    {
        "label": "ZIP Archive",
        "magic": [0x50, 0x4B, 0x03, 0x04],   # spells "PK"
        "ext":   ["zip", "jar", "apk"],
        "threat": False,
    },
    {
        "label": "RAR Archive",
        "magic": [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],  # spells "Rar!"
        "ext":   ["rar"],
        "threat": False,
    },
    {
        "label": "7-Zip Archive",
        "magic": [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
        "ext":   ["7z"],
        "threat": False,
    },
    {
        "label": "GZip Archive",
        "magic": [0x1F, 0x8B],
        "ext":   ["gz", "tgz"],
        "threat": False,
    },
    {
        "label": "XZ Archive",
        "magic": [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],
        "ext":   ["xz"],
        "threat": False,
    },

    # ── Executables — THESE CAN RUN CODE (high risk) ──────────────────
    {
        "label": "Windows Executable / DLL",
        "magic": [0x4D, 0x5A],               # spells "MZ" — famous signature
        "ext":   ["exe", "dll", "sys", "scr"],
        "threat": True,
    },
    {
        "label": "Linux / Unix ELF Executable",
        "magic": [0x7F, 0x45, 0x4C, 0x46],  # spells ".ELF"
        "ext":   ["elf", "so", "out"],
        "threat": True,
    },
    {
        "label": "Java Class File",
        "magic": [0xCA, 0xFE, 0xBA, 0xBE],  # spells "CAFEBABE" — famous!
        "ext":   ["class"],
        "threat": True,
    },
    {
        "label": "Android DEX Bytecode",
        "magic": [0x64, 0x65, 0x78, 0x0A],  # spells "dex\n"
        "ext":   ["dex"],
        "threat": True,
    },
    {
        "label": "WebAssembly Module",
        "magic": [0x00, 0x61, 0x73, 0x6D],  # spells "\0asm"
        "ext":   ["wasm"],
        "threat": True,
    },
    {
        "label": "Python Bytecode",
        "magic": [0x6F, 0x0D, 0x0D, 0x0A],
        "ext":   ["pyc"],
        "threat": True,
    },

    # ── Audio / Video ────────────────────────────────────────────────────
    {
        "label": "MP3 Audio",
        "magic": [0x49, 0x44, 0x33],         # spells "ID3"
        "ext":   ["mp3"],
        "threat": False,
    },
    {
        "label": "FLAC Audio",
        "magic": [0x66, 0x4C, 0x61, 0x43],  # spells "fLaC"
        "ext":   ["flac"],
        "threat": False,
    },
    {
        "label": "OGG Audio / Video",
        "magic": [0x4F, 0x67, 0x67, 0x53],  # spells "OggS"
        "ext":   ["ogg", "ogv"],
        "threat": False,
    },
    {
        "label": "MP4 Video",
        "magic": [0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70],
        "ext":   ["mp4", "m4v"],
        "threat": False,
    },
    {
        "label": "WebM Video",
        "magic": [0x1A, 0x45, 0xDF, 0xA3],
        "ext":   ["webm", "mkv"],
        "threat": False,
    },

    # ── Other ────────────────────────────────────────────────────────────
    {
        "label": "SQLite Database",
        "magic": [0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20,
                  0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00],
        "ext":   ["sqlite", "db", "sqlite3"],
        "threat": False,
    },
    {
        "label": "PCAP Network Capture",
        "magic": [0xD4, 0xC3, 0xB2, 0xA1],
        "ext":   ["pcap"],
        "threat": False,
    },
    {
        "label": "X.509 Certificate",
        "magic": [0x30, 0x82],
        "ext":   ["der", "cer", "crt"],
        "threat": False,
    },
]

# These extensions are always suspicious on their own,
# even if we can't read a magic number from the file.
SUSPICIOUS_EXTENSIONS = [
    "exe", "dll", "bat", "sh", "cmd", "ps1",
    "vbs", "scr", "com", "hta", "msi", "lnk",
]
