import datetime

from google.auth.exceptions import GoogleAuthError
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request

from django.conf import settings
from django.utils.timezone import now
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from ..google_auth import get_google_auth_url, get_google_credentials
from django.shortcuts import redirect, render
from django.http import JsonResponse

class GoogleAuthView(APIView):
    """Generates Google OAuth URL for user authentication."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        auth_url = get_google_auth_url(request)
        return Response({"auth_url": auth_url})

def get_valid_google_token(user):
    if user.google_access_token and user.google_token_expiry and user.google_token_expiry > now():
        return user.google_access_token

    if not user.google_refresh_token:
        return None

    creds = Credentials(
        token=user.google_access_token,
        refresh_token=user.google_refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.GOOGLE_OAUTH_CLIENT_ID,
        client_secret=settings.GOOGLE_OAUTH_CLIENT_SECRET,
    )
    creds.refresh(Request())
    user.google_access_token = creds.token
    user.google_token_expiry = now() + datetime.timedelta(seconds=3600)
    user.save()
    return creds.token

def google_login(request):
    if request.user.google_access_token:
        return redirect("google-sheets")

    auth_url = get_google_auth_url(request)
    return redirect(auth_url)

def google_auth_callback(request):
    code = request.GET.get("code")
    if not code:
        return JsonResponse({"error": "No authorization code received"}, status=400)

    try:
        credentials = get_google_credentials(code, request)
    except Exception as e:
        return JsonResponse({"error": f"Failed to fetch credentials: {str(e)}"}, status=400)

    user = request.user
    user.google_access_token = credentials.token
    user.google_refresh_token = credentials.refresh_token
    user.google_token_expiry = credentials.expiry
    user.save()

    return redirect("google-sheets")


def google_fetch_sheets(request):
    """ Fetch list of Google Sheets from user's Google Drive """
    user = request.user
    access_token = get_valid_google_token(user)

    if not access_token:
        return redirect("google_login")

    creds = Credentials(token=access_token)

    try:
        service = build("drive", "v3", credentials=creds)
        results = service.files().list(
            q="mimeType='application/vnd.google-apps.spreadsheet'",
            fields="files(id, name)",
            pageSize=100
        ).execute()

        files = results.get("files", [])
        sheets = [{"sheet_id": f["id"], "title": f["name"]} for f in files]

        # Return JSON if requested (useful for frontend AJAX)
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return JsonResponse({"sheets": sheets})

        return render(request, "connectors/google.html", {"sheets": sheets})

    except GoogleAuthError as err:
        return JsonResponse({"error": f"Google authentication error: {err}"}, status=401)
    except Exception as e:
        return JsonResponse({"error": f"An error occurred: {str(e)}"}, status=500)


def google_fetch_sheet_data(request):
    """Fetch data from a selected Google Sheet"""
    spreadsheet_id = request.GET.get("spreadsheet_id")

    if not spreadsheet_id:
        return Response({"error": "Missing spreadsheet_id parameter."}, status=400)

    user = request.user
    access_token = get_valid_google_token(user)

    if not access_token:
        return Response({"error": "Google authentication required."}, status=401)

    creds = Credentials(token=access_token)

    try:
        service = build("sheets", "v4", credentials=creds)
        result = service.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id, range="Sheet1"
        ).execute()

        rows = result.get("values", [])
        return JsonResponse({"data": rows if rows else "No data found."})

    except GoogleAuthError as err:
        return JsonResponse({"error": f"Google authentication error: {err}"}, status=401)
    except Exception as e:
        return JsonResponse({"error": f"Failed to fetch sheet data: {str(e)}"}, status=500)