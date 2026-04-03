import uuid

from django.db import models


class ScanFile(models.Model):
    file = models.FileField(upload_to='uploads/')
    filename = models.CharField(max_length=255)
    content_type = models.CharField(max_length=100, blank=True)
    sha256 = models.CharField(max_length=64, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.filename


class ScanJob(models.Model):
    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    scan_file = models.OneToOneField(ScanFile, on_delete=models.CASCADE, related_name="scan_job")
    public_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.QUEUED)
    error_message = models.TextField(blank=True)
    requested_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.scan_file.filename} - {self.get_status_display()}"


class ScanResult(models.Model):
    scan_file = models.OneToOneField(ScanFile, on_delete=models.CASCADE)
    risk_score = models.FloatField(default=0.0)
    risk_level = models.CharField(max_length=20, default='Unknown')
    entropy = models.FloatField(default=0.0)
    file_size = models.BigIntegerField(default=0)
    file_extension = models.CharField(max_length=20, blank=True)
    file_type = models.CharField(max_length=50, blank=True)
    content_type = models.CharField(max_length=100, blank=True)
    is_executable = models.BooleanField(default=False)
    contains_embedded_urls = models.BooleanField(default=False)
    contains_base64_strings = models.BooleanField(default=False)
    suspicious_string_count = models.PositiveIntegerField(default=0)
    suspicious_api_count = models.PositiveIntegerField(default=0)
    yara_match_count = models.PositiveIntegerField(default=0)
    yara_available = models.BooleanField(default=True)
    scan_duration_ms = models.PositiveIntegerField(default=0)
    analysis_version = models.CharField(max_length=20, default="2026.03")
    suspicious_strings = models.TextField(blank=True)
    suspicious_apis = models.TextField(blank=True)
    yara_matches = models.TextField(blank=True)
    explanation = models.TextField(blank=True)
    scanned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.scan_file.filename} - {self.risk_level}"
