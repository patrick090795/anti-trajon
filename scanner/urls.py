from django.urls import path
from . import views

urlpatterns = [
    path('', views.scan_home, name='scan_home'),
    path('jobs/<uuid:scan_job_public_id>/status/', views.scan_job_status, name='scan_job_status'),
    path('result/<int:scan_file_id>/', views.scan_result, name='scan_result'),
    path('dashboard/', views.dashboard_redirect, name='scanner_dashboard'),
    path('history/', views.scan_history, name='scan_history'),
]
