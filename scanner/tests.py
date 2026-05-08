from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse

from .models import ScanFile, ScanJob, ScanResult
from .services import yara_engine
from .services.analysis_pipeline import calculate_sha256, run_scan_pipeline
from .tasks import try_complete_scan_job_from_existing_result
from .services.scoring import build_scan_result_data


class ScanWorkflowTests(TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.override = override_settings(MEDIA_ROOT=self.temp_dir.name)
        self.override.enable()
        self.user = get_user_model().objects.create_user(username="analyst", password="safe-pass-123")
        self.client.force_login(self.user)

    def tearDown(self):
        self.override.disable()
        self.temp_dir.cleanup()

    @override_settings(SCAN_EAGER_JOBS=True)
    @patch("scanner.services.analysis_pipeline.get_yara_scan_report", return_value={"matches": ["trojan_rule"], "available": True})
    @patch("scanner.services.analysis_pipeline.analyze_pe_imports", return_value=["CreateRemoteThread"])
    @patch("scanner.services.analysis_pipeline.detect_suspicious_strings", return_value=["powershell", "http"])
    @patch(
        "scanner.services.analysis_pipeline.extract_basic_features",
        return_value={
            "file_size": 128,
            "extension": ".bin",
            "entropy": 7.8,
            "file_type": "Portable Executable",
            "content_type": "application/octet-stream",
            "is_executable": True,
            "contains_embedded_urls": True,
            "contains_base64_strings": False,
        },
    )
    def test_scan_home_persists_analysis_fields(
        self,
        mock_features,
        mock_strings,
        mock_imports,
        mock_yara_report,
    ):
        upload = SimpleUploadedFile("sample.bin", b"test payload", content_type="application/octet-stream")

        response = self.client.post(reverse("scan_home"), {"file": upload})

        self.assertEqual(response.status_code, 200)
        result = ScanResult.objects.select_related("scan_file").get()
        self.assertEqual(result.scan_file.uploaded_by, self.user)
        self.assertEqual(result.risk_level, "High")
        self.assertEqual(result.risk_score, 135)
        self.assertEqual(result.entropy, 7.8)
        self.assertEqual(result.file_size, 128)
        self.assertEqual(result.file_extension, ".bin")
        self.assertEqual(result.file_type, "Portable Executable")
        self.assertEqual(result.content_type, "application/octet-stream")
        self.assertTrue(result.is_executable)
        self.assertTrue(result.contains_embedded_urls)
        self.assertFalse(result.contains_base64_strings)
        self.assertEqual(result.suspicious_string_count, 2)
        self.assertEqual(result.suspicious_api_count, 1)
        self.assertEqual(result.yara_match_count, 1)
        self.assertTrue(result.yara_available)
        self.assertEqual(result.suspicious_strings, "powershell, http")
        self.assertEqual(result.suspicious_apis, "CreateRemoteThread")
        self.assertEqual(result.yara_matches, "trojan_rule")
        self.assertContains(response, "sample.bin")
        self.assertEqual(ScanJob.objects.get().status, ScanJob.Status.COMPLETED)

        mock_features.assert_called_once()
        mock_strings.assert_called_once()
        mock_imports.assert_called_once()
        mock_yara_report.assert_called_once()

    @patch("scanner.views.schedule_scan_job")
    def test_scan_home_queues_background_job_before_result_is_ready(self, mock_schedule_scan_job):
        upload = SimpleUploadedFile("queued.bin", b"queued payload", content_type="application/octet-stream")

        response = self.client.post(reverse("scan_home"), {"file": upload})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Scan queued")
        queued_job = ScanJob.objects.get()
        self.assertEqual(queued_job.status, ScanJob.Status.QUEUED)
        mock_schedule_scan_job.assert_called_once_with(queued_job.id)

    @patch("scanner.services.analysis_pipeline.get_yara_scan_report", return_value={"matches": ["trojan_rule"], "available": True})
    @patch("scanner.services.analysis_pipeline.analyze_pe_imports", return_value=["CreateRemoteThread"])
    @patch("scanner.services.analysis_pipeline.detect_suspicious_strings", return_value=["powershell", "http"])
    @patch(
        "scanner.services.analysis_pipeline.extract_basic_features",
        return_value={
            "file_size": 128,
            "extension": ".bin",
            "entropy": 7.8,
            "file_type": "Portable Executable",
            "content_type": "application/octet-stream",
            "is_executable": True,
            "contains_embedded_urls": True,
            "contains_base64_strings": False,
        },
    )
    def test_analysis_pipeline_creates_scan_records(
        self,
        mock_features,
        mock_strings,
        mock_imports,
        mock_yara_report,
    ):
        upload = SimpleUploadedFile("pipeline.bin", b"test payload", content_type="application/octet-stream")

        scan_file, result = run_scan_pipeline(upload)

        self.assertEqual(scan_file.filename, "pipeline.bin")
        self.assertEqual(scan_file.content_type, "application/octet-stream")
        self.assertEqual(len(scan_file.sha256), 64)
        self.assertEqual(result.scan_file, scan_file)
        self.assertEqual(result.risk_level, "High")
        self.assertEqual(result.risk_score, 135)
        self.assertEqual(result.suspicious_apis, "CreateRemoteThread")
        self.assertEqual(result.yara_matches, "trojan_rule")
        self.assertEqual(result.file_type, "Portable Executable")
        self.assertTrue(result.contains_embedded_urls)

        mock_features.assert_called_once()
        mock_strings.assert_called_once()
        mock_imports.assert_called_once()
        mock_yara_report.assert_called_once()

    def test_scan_history_page_renders_saved_results(self):
        self.client.force_login(self.user)
        scan_file = ScanFile.objects.create(
            file="uploads/history.bin",
            filename="history.bin",
            sha256="a" * 64,
            uploaded_by=self.user,
        )
        ScanResult.objects.create(
            scan_file=scan_file,
            risk_score=35,
            risk_level="Medium",
            entropy=6.4,
            file_size=256,
            file_extension=".bin",
            suspicious_strings="http",
            suspicious_apis="",
            yara_matches="",
            explanation="Sample explanation",
        )

        response = self.client.get(reverse("scan_history"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "scanner/history.html")
        self.assertContains(response, "history.bin")
        self.assertContains(response, "Medium")

    def test_scan_history_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("scan_history"))

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)

    def test_scan_result_requires_login(self):
        self.client.logout()
        scan_file = ScanFile.objects.create(
            file="uploads/protected.bin",
            filename="protected.bin",
            sha256="d" * 64,
            uploaded_by=self.user,
        )
        ScanResult.objects.create(
            scan_file=scan_file,
            risk_score=10,
            risk_level="Low",
            explanation="Protected result",
        )

        response = self.client.get(reverse("scan_result", args=[scan_file.id]))

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)

    def test_root_url_redirects_to_scan_home(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse("scan_home"))

    def test_scoring_service_builds_high_risk_payload(self):
        result_data = build_scan_result_data(
            {"file_size": 512, "extension": ".exe", "entropy": 7.7},
            ["powershell"],
            ["CreateRemoteThread"],
            ["trojan_rule"],
        )

        self.assertEqual(result_data["risk_score"], 125)
        self.assertEqual(result_data["risk_level"], "High")
        self.assertEqual(result_data["file_extension"], ".exe")
        self.assertIn("Heuristics triggered:", result_data["explanation"])

    @patch("scanner.services.analysis_pipeline.get_yara_scan_report", return_value={"matches": [], "available": True})
    @patch("scanner.services.analysis_pipeline.analyze_pe_imports", return_value=[])
    @patch("scanner.services.analysis_pipeline.detect_suspicious_strings", return_value=[])
    @patch(
        "scanner.services.analysis_pipeline.extract_basic_features",
        return_value={
            "file_size": 24,
            "extension": ".txt",
            "entropy": 1.2,
            "file_type": "Text",
            "content_type": "text/plain",
            "is_executable": False,
            "contains_embedded_urls": False,
            "contains_base64_strings": False,
        },
    )
    def test_analysis_pipeline_marks_clean_file_as_low_risk(
        self,
        mock_features,
        mock_strings,
        mock_imports,
        mock_yara_report,
    ):
        upload = SimpleUploadedFile("clean.txt", b"hello world", content_type="text/plain")

        scan_file, result = run_scan_pipeline(upload)

        self.assertEqual(scan_file.filename, "clean.txt")
        self.assertEqual(result.risk_score, 0)
        self.assertEqual(result.risk_level, "Low")
        self.assertEqual(result.suspicious_strings, "")
        self.assertEqual(result.suspicious_apis, "")
        self.assertEqual(result.yara_matches, "")
        self.assertIn("No heuristic rules triggered.", result.explanation)

        mock_features.assert_called_once()
        mock_strings.assert_called_once()
        mock_imports.assert_called_once()
        mock_yara_report.assert_called_once()

    def test_scan_job_status_returns_completed_result_fragment(self):
        scan_file = ScanFile.objects.create(
            file="uploads/done.bin",
            filename="done.bin",
            content_type="application/octet-stream",
            sha256="e" * 64,
            uploaded_by=self.user,
        )
        scan_job = ScanJob.objects.create(scan_file=scan_file, status=ScanJob.Status.COMPLETED)
        ScanResult.objects.create(
            scan_file=scan_file,
            risk_score=65,
            risk_level="High",
            entropy=7.9,
            file_size=512,
            file_extension=".bin",
            explanation="Done",
        )

        response = self.client.get(reverse("scan_job_status", args=[scan_job.public_id]), HTTP_HX_REQUEST="true")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="upload-panel"')
        self.assertContains(response, "done.bin")

    def test_scan_job_status_returns_failed_state(self):
        scan_file = ScanFile.objects.create(
            file="uploads/failed.bin",
            filename="failed.bin",
            content_type="application/octet-stream",
            sha256="f" * 64,
            uploaded_by=self.user,
        )
        scan_job = ScanJob.objects.create(
            scan_file=scan_file,
            status=ScanJob.Status.FAILED,
            error_message="Worker crashed",
        )

        response = self.client.get(reverse("scan_job_status", args=[scan_job.public_id]), HTTP_HX_REQUEST="true")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Scan failed")
        self.assertContains(response, "Worker crashed")

    @override_settings(MAX_SCAN_UPLOAD_SIZE=4)
    def test_oversized_upload_is_rejected(self):
        upload = SimpleUploadedFile("large.bin", b"12345", content_type="application/octet-stream")

        response = self.client.post(reverse("scan_home"), {"file": upload})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "File is too large. Maximum allowed size is 4 bytes.")
        self.assertEqual(ScanFile.objects.count(), 0)
        self.assertEqual(ScanResult.objects.count(), 0)

    def test_empty_upload_is_rejected(self):
        upload = SimpleUploadedFile("empty.bin", b"", content_type="application/octet-stream")

        response = self.client.post(reverse("scan_home"), {"file": upload})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Empty files cannot be scanned.")
        self.assertEqual(ScanFile.objects.count(), 0)
        self.assertEqual(ScanResult.objects.count(), 0)

    def test_upload_without_supported_extension_is_rejected(self):
        upload = SimpleUploadedFile("sample", b"test payload", content_type="application/octet-stream")

        response = self.client.post(reverse("scan_home"), {"file": upload})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Unsupported file type. Supported extensions:")
        self.assertEqual(ScanFile.objects.count(), 0)
        self.assertEqual(ScanResult.objects.count(), 0)

    def test_unsupported_extension_is_rejected(self):
        upload = SimpleUploadedFile("photo.jpg", b"not really an image", content_type="image/jpeg")

        response = self.client.post(reverse("scan_home"), {"file": upload})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Unsupported file type &#x27;.jpg&#x27;.")
        self.assertEqual(ScanFile.objects.count(), 0)
        self.assertEqual(ScanResult.objects.count(), 0)

    def test_supported_extension_with_unsupported_content_type_is_rejected(self):
        upload = SimpleUploadedFile("script.py", b"print('hello')", content_type="image/jpeg")

        response = self.client.post(reverse("scan_home"), {"file": upload})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Unsupported content type &#x27;image/jpeg&#x27; for .py files.")
        self.assertEqual(ScanFile.objects.count(), 0)
        self.assertEqual(ScanResult.objects.count(), 0)

    @override_settings(MAX_SCAN_UPLOAD_SIZE=4)
    def test_htmx_invalid_upload_returns_oob_form_update(self):
        upload = SimpleUploadedFile("large.bin", b"12345", content_type="application/octet-stream")

        response = self.client.post(
            reverse("scan_home"),
            {"file": upload},
            HTTP_HX_REQUEST="true",
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="upload-panel"')
        self.assertContains(response, 'hx-swap-oob="true"')
        self.assertContains(response, "File is too large. Maximum allowed size is 4 bytes.")
        self.assertEqual(ScanFile.objects.count(), 0)

    @patch("scanner.services.analysis_pipeline.extract_basic_features")
    def test_run_scan_pipeline_does_not_reuse_other_users_result(self, mock_extract_basic_features):
        other_user = get_user_model().objects.create_user(username="other", password="safe-pass-123")
        sample_bytes = b"Write-Host 'Hello'"
        sample_hash = calculate_sha256(SimpleUploadedFile("sample.ps1", sample_bytes, content_type="text/plain"))
        source_scan_file = ScanFile.objects.create(
            file="uploads/sample.ps1",
            filename="sample.ps1",
            content_type="text/plain",
            sha256=sample_hash,
            uploaded_by=other_user,
        )
        ScanResult.objects.create(
            scan_file=source_scan_file,
            risk_score=25,
            risk_level="Medium",
            entropy=4.0,
            file_size=len(sample_bytes),
            file_extension=".ps1",
            file_type="PowerShell script",
            content_type="text/plain",
            is_executable=True,
            suspicious_strings="powershell",
            suspicious_string_count=1,
            explanation="Existing result",
        )
        mock_extract_basic_features.return_value = {
            "file_size": len(sample_bytes),
            "extension": ".ps1",
            "entropy": 4.0,
            "file_type": "PowerShell script",
            "content_type": "text/plain",
            "is_executable": True,
            "contains_embedded_urls": False,
            "contains_base64_strings": False,
        }

        upload = SimpleUploadedFile("sample.ps1", sample_bytes, content_type="text/plain")
        scan_file, result = run_scan_pipeline(upload, uploaded_by=self.user)

        self.assertEqual(scan_file.uploaded_by, self.user)
        self.assertFalse(result.reused_existing_analysis)
        self.assertIsNone(result.source_result)
        mock_extract_basic_features.assert_called_once()

    @patch("scanner.services.analysis_pipeline.extract_basic_features")
    def test_run_scan_pipeline_reuse_keeps_current_submission_metadata(self, mock_extract_basic_features):
        sample_bytes = b"Write-Host 'Hello'"
        sample_hash = calculate_sha256(SimpleUploadedFile("sample.ps1", sample_bytes, content_type="text/plain"))
        source_scan_file = ScanFile.objects.create(
            file="uploads/sample.ps1",
            filename="sample.ps1",
            content_type="text/plain",
            sha256=sample_hash,
            uploaded_by=self.user,
        )
        source_result = ScanResult.objects.create(
            scan_file=source_scan_file,
            risk_score=25,
            risk_level="Medium",
            entropy=4.0,
            file_size=len(sample_bytes),
            file_extension=".ps1",
            file_type="PowerShell script",
            content_type="text/plain",
            is_executable=True,
            suspicious_strings="powershell",
            suspicious_string_count=1,
            explanation="Existing result",
        )

        upload = SimpleUploadedFile("renamed.txt", sample_bytes, content_type="text/plain")
        scan_file, result = run_scan_pipeline(upload, uploaded_by=self.user)

        self.assertTrue(result.reused_existing_analysis)
        self.assertEqual(result.source_result, source_result)
        self.assertEqual(result.file_extension, ".txt")
        self.assertEqual(result.file_type, "Text")
        self.assertEqual(result.content_type, "text/plain")
        self.assertFalse(result.is_executable)
        mock_extract_basic_features.assert_not_called()

    def test_reused_result_api_and_report_hide_source_ids_for_non_staff(self):
        source_scan_file = ScanFile.objects.create(
            file="uploads/original.bin",
            filename="original.bin",
            content_type="application/octet-stream",
            sha256="1" * 64,
            uploaded_by=self.user,
        )
        source_result = ScanResult.objects.create(
            scan_file=source_scan_file,
            risk_score=65,
            risk_level="High",
            entropy=7.9,
            file_size=512,
            file_extension=".bin",
            content_type="application/octet-stream",
            source_result=None,
            explanation="Original result",
        )
        reused_scan_file = ScanFile.objects.create(
            file="uploads/reused.bin",
            filename="reused.bin",
            content_type="application/octet-stream",
            sha256="1" * 64,
            uploaded_by=self.user,
        )
        reused_result = ScanResult.objects.create(
            scan_file=reused_scan_file,
            source_result=source_result,
            reused_existing_analysis=True,
            risk_score=65,
            risk_level="High",
            entropy=7.9,
            file_size=512,
            file_extension=".bin",
            content_type="application/octet-stream",
            explanation="Reused result",
        )
        ScanJob.objects.create(scan_file=reused_scan_file, status=ScanJob.Status.COMPLETED)

        api_response = self.client.get(reverse("api_scan_result_detail", args=[reused_scan_file.id]))
        report_response = self.client.get(reverse("scan_result_report", args=[reused_scan_file.id]))

        self.assertEqual(api_response.status_code, 200)
        self.assertIsNone(api_response.json()["result"]["source_result_id"])
        self.assertIsNone(api_response.json()["result"]["source_scan_file_id"])
        self.assertEqual(report_response.status_code, 200)
        self.assertIsNone(report_response.json()["analysis"]["source_result_id"])
        self.assertIsNone(report_response.json()["analysis"]["source_scan_file_id"])
        self.assertTrue(reused_result.reused_existing_analysis)

    def test_try_complete_scan_job_marks_job_failed_when_reuse_errors(self):
        sample_bytes = b"Write-Host 'Hello'"
        sample_hash = calculate_sha256(SimpleUploadedFile("sample.ps1", sample_bytes, content_type="text/plain"))
        source_scan_file = ScanFile.objects.create(
            file="uploads/sample.ps1",
            filename="sample.ps1",
            content_type="text/plain",
            sha256=sample_hash,
            uploaded_by=self.user,
        )
        ScanResult.objects.create(
            scan_file=source_scan_file,
            risk_score=25,
            risk_level="Medium",
            entropy=4.0,
            file_size=len(sample_bytes),
            file_extension=".ps1",
            file_type="PowerShell script",
            content_type="text/plain",
            is_executable=True,
            suspicious_strings="powershell",
            suspicious_string_count=1,
            explanation="Existing result",
        )

        upload = SimpleUploadedFile("sample.ps1", sample_bytes, content_type="text/plain")
        response = self.client.post(
            reverse("api_scan_submit"),
            {"file": upload},
        )
        self.assertEqual(response.status_code, 201)

        queued_scan_file = ScanFile.objects.exclude(id=source_scan_file.id).get()
        queued_job = ScanJob.objects.get(scan_file=queued_scan_file)
        queued_job.status = ScanJob.Status.QUEUED
        queued_job.started_at = None
        queued_job.completed_at = None
        queued_job.error_message = ""
        queued_job.save(update_fields=["status", "started_at", "completed_at", "error_message", "updated_at"])
        ScanResult.objects.filter(scan_file=queued_scan_file).delete()

        with patch("scanner.tasks.reuse_existing_result", side_effect=RuntimeError("reuse failed")):
            succeeded = try_complete_scan_job_from_existing_result(queued_job.id)

        queued_job.refresh_from_db()
        self.assertFalse(succeeded)
        self.assertEqual(queued_job.status, ScanJob.Status.FAILED)
        self.assertEqual(queued_job.error_message, "reuse failed")


class YaraEngineTests(TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        yara_engine._compile_rules.cache_clear()

    def tearDown(self):
        yara_engine._compile_rules.cache_clear()

    def test_scan_with_yara_caches_compiled_rules(self):
        rules_path = Path(self.temp_dir.name) / "rules.yar"
        sample_path = Path(self.temp_dir.name) / "sample.bin"
        rules_path.write_text('rule demo_rule { condition: true }', encoding="utf-8")
        sample_path.write_bytes(b"sample")

        match = Mock(rule="demo_rule")
        compiled_rules = Mock()
        compiled_rules.match.return_value = [match]
        yara_module = Mock()
        yara_module.compile.return_value = compiled_rules

        with patch("scanner.services.yara_engine.get_rules_path", return_value=rules_path):
            with patch("scanner.services.yara_engine.import_yara", return_value=yara_module):
                first_result = yara_engine.scan_with_yara(str(sample_path))
                second_result = yara_engine.scan_with_yara(str(sample_path))

        self.assertEqual(first_result, ["demo_rule"])
        self.assertEqual(second_result, ["demo_rule"])
        self.assertEqual(yara_module.compile.call_count, 1)
        self.assertEqual(compiled_rules.match.call_count, 2)

    def test_scan_with_yara_returns_empty_list_when_compile_fails(self):
        rules_path = Path(self.temp_dir.name) / "rules.yar"
        sample_path = Path(self.temp_dir.name) / "sample.bin"
        rules_path.write_text('rule broken_rule { condition: true }', encoding="utf-8")
        sample_path.write_bytes(b"sample")
        yara_module = Mock()
        yara_module.compile.side_effect = RuntimeError("compile failed")

        with self.assertLogs("scanner.services.yara_engine", level="ERROR") as captured_logs:
            with patch("scanner.services.yara_engine.get_rules_path", return_value=rules_path):
                with patch("scanner.services.yara_engine.import_yara", return_value=yara_module):
                    result = yara_engine.scan_with_yara(str(sample_path))

        self.assertEqual(result, [])
        self.assertTrue(any("YARA scanning failed" in message for message in captured_logs.output))

    def test_scan_with_yara_returns_empty_list_when_match_fails(self):
        rules_path = Path(self.temp_dir.name) / "rules.yar"
        sample_path = Path(self.temp_dir.name) / "sample.bin"
        rules_path.write_text('rule demo_rule { condition: true }', encoding="utf-8")
        sample_path.write_bytes(b"sample")

        compiled_rules = Mock()
        compiled_rules.match.side_effect = RuntimeError("match failed")
        yara_module = Mock()
        yara_module.compile.return_value = compiled_rules

        with self.assertLogs("scanner.services.yara_engine", level="ERROR") as captured_logs:
            with patch("scanner.services.yara_engine.get_rules_path", return_value=rules_path):
                with patch("scanner.services.yara_engine.import_yara", return_value=yara_module):
                    result = yara_engine.scan_with_yara(str(sample_path))

        self.assertEqual(result, [])
        self.assertTrue(any("YARA scanning failed" in message for message in captured_logs.output))

    def test_scan_with_yara_returns_empty_list_when_import_fails(self):
        sample_path = Path(self.temp_dir.name) / "sample.bin"
        sample_path.write_bytes(b"sample")

        with self.assertLogs("scanner.services.yara_engine", level="ERROR") as captured_logs:
            with patch("scanner.services.yara_engine.import_yara", side_effect=ImportError("blocked by policy")):
                result = yara_engine.scan_with_yara(str(sample_path))

        self.assertEqual(result, [])
        self.assertTrue(any("YARA scanning failed" in message for message in captured_logs.output))
