import re

# -------------------------------
# General settings
# -------------------------------
ARTIFACT_FILE_NAME = "artifacts.txt"
SUSPICIOUS_ENTROPY_MINVALUE = 7

# -------------------------------
# Regex patterns
# -------------------------------
PATTERNS = [
    (
        "domain",
        re.compile(
            r'\b(?:https?://|www\.)[a-zA-Z0-9\-._~%]+'
            r'(?:\.[a-zA-Z0-9\-._~%]+)+'
            r'(?:/[^\s]*)?'
        ),
    ),
    (
        "ip",
        re.compile(
            r'\b('
            r'(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.'
            r'(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.'
            r'(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.'
            r'(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
            r')\b'
        ),
    ),
    (
        "email",
        re.compile(
            r'[a-zA-Z0-9._%+-]{1,64}'
            r'@[a-zA-Z0-9.-]{1,255}'
            r'\.[a-zA-Z]{2,24}'
        ),
    ),
    (
        "registry",
        re.compile(
            r'\b('
            r'HKEY_LOCAL_MACHINE|'
            r'HKEY_CURRENT_USER|'
            r'HKEY_CLASSES_ROOT|'
            r'HKEY_USERS|'
            r'HKEY_CURRENT_CONFIG|'
            r'HKLM'
            r')'
            r'(\\[A-Za-z0-9_ -]+)+'
            r'\b'
        ),
    ),
    (
        "mutex",
        re.compile(
            r'(?:Global\\|Local\\)?[\w\-_]{3,50}Mutex(?:A|W)?',
            re.IGNORECASE,
        ),
    ),
     (
        "binary_file",
        re.compile(
            r'\b\w+\.(exe|dll|bin)\b',  
            re.IGNORECASE
        ),
    ),
]
