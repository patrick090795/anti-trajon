from django.conf import settings
from django.contrib import admin

from .models import ScanFile, ScanJob, ScanResult

admin.site.site_header = settings.ADMIN_SITE_HEADER
admin.site.site_title = settings.ADMIN_SITE_TITLE
admin.site.index_title = settings.ADMIN_INDEX_TITLE

admin.site.register(ScanFile)
admin.site.register(ScanJob)
admin.site.register(ScanResult)


