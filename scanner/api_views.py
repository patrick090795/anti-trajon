from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.authentication import BasicAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .access import filter_scan_jobs_for_user, filter_scan_results_for_user
from .forms import ScanUploadForm
from .models import ScanJob, ScanResult
from .serializers import ScanJobSerializer, ScanResultSerializer
from .services.analysis_pipeline import persist_uploaded_file
from .services.reporting import build_scan_report
from .tasks import schedule_scan_job


class AuthenticatedApiView(APIView):
    authentication_classes = [SessionAuthentication, BasicAuthentication]
    permission_classes = [IsAuthenticated]


class ScanSubmissionApiView(AuthenticatedApiView):
    def post(self, request):
        form = ScanUploadForm(request.POST, request.FILES)
        if not form.is_valid():
            return Response({"errors": form.errors}, status=status.HTTP_400_BAD_REQUEST)

        uploaded_file = form.cleaned_data["file"]
        scan_file = persist_uploaded_file(uploaded_file, uploaded_by=request.user)
        scan_job = ScanJob.objects.create(scan_file=scan_file)
        schedule_scan_job(scan_job.id)
        scan_job.refresh_from_db()

        response_payload = {
            "scan_file_id": scan_file.id,
            "job": ScanJobSerializer(scan_job, context={"request": request}).data,
            "result": None,
        }

        result = getattr(scan_file, "scanresult", None)
        if result is not None:
            response_payload["result"] = ScanResultSerializer(result, context={"request": request}).data
            response_payload["report"] = build_scan_report(scan_file, result, request=request)
            return Response(response_payload, status=status.HTTP_201_CREATED)

        return Response(response_payload, status=status.HTTP_202_ACCEPTED)


class ScanJobDetailApiView(AuthenticatedApiView):
    def get(self, request, scan_job_public_id):
        scan_job = get_object_or_404(
            filter_scan_jobs_for_user(
                ScanJob.objects.select_related("scan_file"),
                request.user,
            ),
            public_id=scan_job_public_id,
        )
        payload = {"job": ScanJobSerializer(scan_job, context={"request": request}).data}
        if hasattr(scan_job.scan_file, "scanresult"):
            payload["result"] = ScanResultSerializer(
                scan_job.scan_file.scanresult,
                context={"request": request},
            ).data
        return Response(payload)


class ScanResultListApiView(AuthenticatedApiView):
    def get(self, request):
        results = filter_scan_results_for_user(
            ScanResult.objects.select_related("scan_file", "scan_file__uploaded_by", "source_result"),
            request.user,
        ).order_by("-scanned_at")[:50]
        return Response({"results": ScanResultSerializer(results, many=True, context={"request": request}).data})


class ScanResultDetailApiView(AuthenticatedApiView):
    def get(self, request, scan_file_id):
        result = get_object_or_404(
            filter_scan_results_for_user(
                ScanResult.objects.select_related(
                    "scan_file",
                    "scan_file__uploaded_by",
                    "scan_file__scan_job",
                    "source_result",
                ),
                request.user,
            ),
            scan_file_id=scan_file_id,
        )
        return Response(
            {
                "result": ScanResultSerializer(result, context={"request": request}).data,
                "report": build_scan_report(result.scan_file, result, request=request),
            }
        )
