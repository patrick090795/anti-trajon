import math
import os
import re
import pefile

SCRIPT_FILE_TYPES = {
    ".bat": "Batch script",
    ".cmd": "Command script",
    ".hta": "HTML application",
    ".js": "JavaScript",
    ".ps1": "PowerShell script",
    ".py": "Python script",
    ".txt": "Text",
    ".vbe": "VBScript encoded",
    ".vbs": "VBScript",
    ".wsf": "Windows Script File",
}
EXECUTABLE_EXTENSIONS = {".bat", ".cmd", ".dll", ".exe", ".hta", ".js", ".ps1", ".sys", ".vbe", ".vbs", ".wsf"}
BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})")


def calculate_entropy(filepath):

    with open(filepath, "rb") as f:
        data = f.read()

    if not data:
        return 0

    byte_counts = [0] * 256

    for byte in data:
        byte_counts[byte] += 1

    entropy = 0

    for count in byte_counts:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)

    return entropy


def infer_file_type(extension, header):
    if header.startswith(b"MZ"):
        return "Portable Executable"
    return SCRIPT_FILE_TYPES.get(extension.lower(), "Binary or unknown")


def detect_embedded_urls(content):
    lower_content = content.lower()
    return any(marker in lower_content for marker in (b"http://", b"https://", b"hxxp://", b"ftp://"))


def detect_base64_strings(content):
    decoded = content.decode("latin-1", errors="ignore")
    return bool(BASE64_PATTERN.search(decoded))


def extract_basic_features(filepath, content_type=""):

    file_size = os.path.getsize(filepath)
    extension = os.path.splitext(filepath)[1]
    with open(filepath, "rb") as f:
        header = f.read(4)
        f.seek(0)
        content = f.read()

    entropy = calculate_entropy(filepath)
    file_type = infer_file_type(extension, header)
    is_executable = extension.lower() in EXECUTABLE_EXTENSIONS or header.startswith(b"MZ")

    return {
        "file_size": file_size,
        "extension": extension,
        "entropy": entropy,
        "file_type": file_type,
        "content_type": content_type or "",
        "is_executable": is_executable,
        "contains_embedded_urls": detect_embedded_urls(content),
        "contains_base64_strings": detect_base64_strings(content),
    }

def detect_suspicious_strings(filepath):

    suspicious_keywords = [
        b"powershell",
        b"cmd.exe",
        b"regsvr32",
        b"rundll32",
        b"certutil",
        b"bitsadmin",
        b"mshta",
        b"wscript",
        b"cscript",
        b"schtasks",
        b"wget",
        b"curl",
        b"download",
        b"http",
        b"https",
        b"hxxp",
        b"Invoke-WebRequest",
        b"Invoke-Expression",
        b"FromBase64String",
        b"base64",
        b"CreateRemoteThread",
        b"WriteProcessMemory",
    ]

    found = set()

    with open(filepath, "rb") as f:
        content = f.read().lower()

    for keyword in suspicious_keywords:
        if keyword.lower() in content:
            found.add(keyword.decode())

    return sorted(found)

# For PE files, analyze imported APIs for suspicious behavior

def analyze_pe_imports(filepath):

    suspicious_apis = [
        "CreateRemoteThread",
        "WriteProcessMemory",
        "VirtualAllocEx",
        "OpenProcess",
        "WinExec",
        "ShellExecuteA",
        "ShellExecuteW",
        "SetWindowsHookEx",
    ]

    found_apis = set()

    try:
        pe = pefile.PE(filepath)

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        api = imp.name.decode()

                        if api in suspicious_apis:
                            found_apis.add(api)

    except Exception:
        # not a PE file
        return []

    return sorted(found_apis)
