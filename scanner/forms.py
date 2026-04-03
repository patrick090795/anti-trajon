from pathlib import Path

from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError


def format_file_size(size_in_bytes):
    if size_in_bytes >= 1024 * 1024:
        return f"{size_in_bytes / (1024 * 1024):.0f} MB"
    if size_in_bytes >= 1024:
        return f"{size_in_bytes / 1024:.0f} KB"
    return f"{size_in_bytes} bytes"


def format_supported_extensions(extensions):
    return ", ".join(sorted(extensions))


class ScanUploadForm(forms.Form):
    file = forms.FileField(
        error_messages={
            "empty": "Empty files cannot be scanned.",
        },
        widget=forms.ClearableFileInput(
            attrs={
                "class": "field-shell block w-full rounded-xl border p-3 text-sm"
            }
        )
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_upload_size = getattr(settings, "MAX_SCAN_UPLOAD_SIZE", 10 * 1024 * 1024)
        self.supported_extensions = tuple(
            extension.lower() for extension in getattr(settings, "SCAN_SUPPORTED_EXTENSIONS", (".bin", ".txt"))
        )
        configured_content_types = getattr(settings, "SCAN_ALLOWED_CONTENT_TYPES", {})
        self.allowed_content_types = {
            extension.lower(): {content_type.lower() for content_type in content_types}
            for extension, content_types in configured_content_types.items()
        }
        self.fields["file"].widget.attrs["accept"] = ",".join(self.supported_extensions)
        self.fields["file"].help_text = (
            f"Maximum file size: {format_file_size(self.max_upload_size)}. "
            f"Supported extensions: {format_supported_extensions(self.supported_extensions)}."
        )

    def clean_file(self):
        uploaded_file = self.cleaned_data["file"]
        extension = Path(uploaded_file.name).suffix.lower()

        if uploaded_file.size == 0:
            raise ValidationError("Empty files cannot be scanned.")

        if uploaded_file.size > self.max_upload_size:
            raise ValidationError(
                f"File is too large. Maximum allowed size is {format_file_size(self.max_upload_size)}."
            )

        if len(uploaded_file.name) > 255:
            raise ValidationError("Filename is too long. Please upload a file with a shorter name.")

        if not extension:
            raise ValidationError(
                f"Unsupported file type. Supported extensions: {format_supported_extensions(self.supported_extensions)}."
            )

        if extension not in self.supported_extensions:
            raise ValidationError(
                f"Unsupported file type '{extension}'. "
                f"Supported extensions: {format_supported_extensions(self.supported_extensions)}."
            )

        content_type = (uploaded_file.content_type or "").split(";", 1)[0].strip().lower()
        allowed_types_for_extension = self.allowed_content_types.get(extension, set())

        if content_type and allowed_types_for_extension and content_type not in allowed_types_for_extension:
            raise ValidationError(
                f"Unsupported content type '{content_type}' for {extension} files."
            )

        return uploaded_file
