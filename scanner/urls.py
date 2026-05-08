from django.urls import path

from .api_views import (
    ScanJobDetailApiView,
    ScanResultDetailApiView,
    ScanResultListApiView,
    ScanSubmissionApiView,
)
from . import views

urlpatterns = [
    path('', views.scan_home, name='scan_home'),
    path('jobs/<uuid:scan_job_public_id>/status/', views.scan_job_status, name='scan_job_status'),
    path('result/<int:scan_file_id>/', views.scan_result, name='scan_result'),
    path('result/<int:scan_file_id>/report.json', views.scan_result_report, name='scan_result_report'),
    path('dashboard/', views.dashboard_redirect, name='scanner_dashboard'),
    path('history/', views.scan_history, name='scan_history'),
    path('api/scans/', ScanSubmissionApiView.as_view(), name='api_scan_submit'),
    path('api/jobs/<uuid:scan_job_public_id>/', ScanJobDetailApiView.as_view(), name='api_scan_job_detail'),
    path('api/results/', ScanResultListApiView.as_view(), name='api_scan_result_list'),
    path('api/results/<int:scan_file_id>/', ScanResultDetailApiView.as_view(), name='api_scan_result_detail'),
]
