from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from scanner.models import ScanFile, ScanResult


class DashboardViewTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="analyst", password="safe-pass-123")

    def test_dashboard_renders_scan_statistics(self):
        self.client.force_login(self.user)
        clean_file = ScanFile.objects.create(
            file="uploads/clean.bin",
            filename="clean.bin",
            sha256="b" * 64,
            uploaded_by=self.user,
        )
        hit_file = ScanFile.objects.create(
            file="uploads/hit.bin",
            filename="hit.bin",
            sha256="c" * 64,
            uploaded_by=self.user,
        )

        ScanResult.objects.create(
            scan_file=clean_file,
            risk_score=10,
            risk_level="Low",
            entropy=3.2,
            file_size=100,
            file_extension=".bin",
            suspicious_strings="",
            suspicious_apis="",
            yara_matches="",
            explanation="Clean sample",
        )
        ScanResult.objects.create(
            scan_file=hit_file,
            risk_score=70,
            risk_level="High",
            entropy=7.6,
            file_size=2048,
            file_extension=".exe",
            suspicious_strings="powershell",
            suspicious_apis="CreateRemoteThread",
            yara_matches="trojan_rule",
            explanation="Malicious sample",
        )

        response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "scanner/dashboard.html")
        self.assertContains(response, "Total Scans")
        self.assertContains(response, "2")
        self.assertContains(response, "hit.bin")
        self.assertContains(response, "trojan_rule")

    def test_dashboard_requires_login(self):
        response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)
