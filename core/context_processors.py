from django.conf import settings


def admin_branding(_request):
    return {
        "admin_brand_name": settings.ADMIN_BRAND_NAME,
        "admin_subtitle": settings.ADMIN_SUBTITLE,
        "admin_footer_note": settings.ADMIN_FOOTER_NOTE,
    }
