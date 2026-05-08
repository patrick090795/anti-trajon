def filter_scan_files_for_user(queryset, user):
    if user.is_staff:
        return queryset
    return queryset.filter(uploaded_by=user)


def filter_scan_results_for_user(queryset, user):
    if user.is_staff:
        return queryset
    return queryset.filter(scan_file__uploaded_by=user)


def filter_scan_jobs_for_user(queryset, user):
    if user.is_staff:
        return queryset
    return queryset.filter(scan_file__uploaded_by=user)
