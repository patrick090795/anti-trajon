from rest_framework import serializers

from .models import ScanFile, ScanJob, ScanResult


class ScanFileSerializer(serializers.ModelSerializer):
    uploaded_by = serializers.CharField(source="uploaded_by.username", read_only=True, allow_null=True)

    class Meta:
        model = ScanFile
        fields = [
            "id",
            "filename",
            "content_type",
            "sha256",
            "uploaded_at",
            "uploaded_by",
        ]


class ScanJobSerializer(serializers.ModelSerializer):
    scan_file_id = serializers.IntegerField(source="scan_file.id", read_only=True)

    class Meta:
        model = ScanJob
        fields = [
            "public_id",
            "scan_file_id",
            "status",
            "error_message",
            "requested_at",
            "started_at",
            "completed_at",
        ]


class ScanResultSerializer(serializers.ModelSerializer):
    scan_file = ScanFileSerializer(read_only=True)
    source_result_id = serializers.SerializerMethodField()
    source_scan_file_id = serializers.SerializerMethodField()

    def _should_expose_source_result_ids(self):
        request = self.context.get("request")
        return bool(request and request.user.is_staff)

    def get_source_result_id(self, obj):
        if not self._should_expose_source_result_ids() or obj.source_result is None:
            return None
        return obj.source_result.id

    def get_source_scan_file_id(self, obj):
        if not self._should_expose_source_result_ids() or obj.source_result is None:
            return None
        return obj.source_result.scan_file_id

    class Meta:
        model = ScanResult
        fields = [
            "scan_file",
            "risk_score",
            "risk_level",
            "entropy",
            "file_size",
            "file_extension",
            "file_type",
            "content_type",
            "is_executable",
            "contains_embedded_urls",
            "contains_base64_strings",
            "suspicious_string_count",
            "suspicious_api_count",
            "yara_match_count",
            "yara_available",
            "scan_duration_ms",
            "analysis_version",
            "reused_existing_analysis",
            "source_result_id",
            "source_scan_file_id",
            "suspicious_strings",
            "suspicious_apis",
            "yara_matches",
            "explanation",
            "scanned_at",
        ]
