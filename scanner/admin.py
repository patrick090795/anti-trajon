from django.contrib import admin

from .models import ScanFile, ScanJob, ScanResult

admin.site.site_header = "Anti-Trojan Administration"
admin.site.site_title = "Anti-Trojan Admin"
admin.site.index_title = "Security Console"

admin.site.register(ScanFile)
admin.site.register(ScanJob)
admin.site.register(ScanResult)


