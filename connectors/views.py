# google_sheets/views.py
import datetime
from datetime import timedelta

from google.auth.exceptions import GoogleAuthError
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from django.utils import timezone

from django.conf import settings
from django.http import HttpResponse
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login, authenticate
from django.utils.timezone import now
from django.views.generic import TemplateView
from django.contrib.auth.decorators import login_required
from googleapiclient.errors import HttpError
from rest_framework.exceptions import server_error
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .google_auth import get_google_auth_url, get_google_credentials
from .models import CustomUser
from .forms import CustomUserCreationForm
import requests
from django.shortcuts import redirect, render
from django.http import JsonResponse

class SignUpView(TemplateView):
    template_name = 'connectors/signup.html'

    def get(self, request):
        form = CustomUserCreationForm()
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=password)
            login(request, user)
            return redirect('landing')  # Redirect to the home page after signup
        return render(request, self.template_name, {'form': form})


class LandingPageView(LoginRequiredMixin, TemplateView):
    template_name = 'connectors/landing.html'

    def get_context_data(self, **kwargs):
        # Pass the logged-in user to the context
        context = super().get_context_data(**kwargs)
        context['user'] = self.request.user  # Ensure user is available in the template context
        return context

class GooglePageView(LoginRequiredMixin, TemplateView):
    template_name = 'connectors/google.html'

    def get_context_data(self, **kwargs):
        # Pass the logged-in user to the context
        context = super().get_context_data(**kwargs)
        context['user'] = self.request.user  # Ensure user is available in the template context
        return context

class MicrosoftPageView(LoginRequiredMixin, TemplateView):
    template_name = 'connectors/microsoft.html'

    def get_context_data(self, **kwargs):
        # Pass the logged-in user to the context
        context = super().get_context_data(**kwargs)
        context['user'] = self.request.user  # Ensure user is available in the template context
        return context

class GoogleAuthView(APIView):
    """Generates Google OAuth URL for user authentication."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        auth_url = get_google_auth_url(request)
        return Response({"auth_url": auth_url})

from django.shortcuts import redirect
from django.contrib import messages


# Utility function to get valid Google token
def get_valid_google_token(user):
    if user.google_access_token and user.google_token_expiry and user.google_token_expiry > now():
        return user.google_access_token

    if not user.google_refresh_token:
        return None  # No valid token available

    # Refresh token request
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
        # If the user already has an access token, redirect them to the Google Sheets page or show a message
        return redirect("google-sheets")  # Adjust this to the page where you show Google Sheets, or show a message

    auth_url = get_google_auth_url(request)
    return redirect(auth_url)

# Google OAuth Callback
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


# Fetch Google Sheets API
def google_fetch_sheets(request):
    user = request.user
    access_token = get_valid_google_token(user)
    if not access_token:
        return redirect("google_login")

    creds = Credentials(token=access_token)
    try:
        service = build("drive", "v3", credentials=creds)
        results = service.files().list(q="mimeType='application/vnd.google-apps.spreadsheet'",
                                       fields="files(id, name)").execute()
        files = results.get("files", [])
        sheets = [{"sheet_id": f["id"], "title": f["name"]} for f in files]
        return render(request, "connectors/google.html", {"sheets": sheets})
    except GoogleAuthError as err:
        return JsonResponse({"error": str(err)}, status=400)


# Fetch Data from a Google Sheet
class GoogleSheetDataView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        spreadsheet_id = request.GET.get("spreadsheet_id")
        user = request.user
        access_token = get_valid_google_token(user)
        if not access_token:
            return Response({"error": "Google authentication required."}, status=401)

        creds = Credentials(token=access_token)
        try:
            service = build("sheets", "v4", credentials=creds)
            result = service.spreadsheets().values().get(spreadsheetId=spreadsheet_id, range="Sheet1").execute()
            rows = result.get("values", [])
            return Response({"data": rows if rows else "No data found."})
        except GoogleAuthError as err:
            return Response({"error": str(err)}, status=400)

# Step 1: Redirect to Microsoft Login
def microsoft_login(request):
    if request.user.microsoft_access_token:  # Check if the user already has a Microsoft access token
        # If the user already has an access token, redirect them to the Microsoft-related page
        return redirect(
            "microsoft_fetch_excel")  # Adjust this to the page where you show Microsoft Excel, or show a message

    auth_url = (
        f"{settings.MICROSOFT_AUTH_URL}?"
        f"client_id={settings.MICROSOFT_CLIENT_ID}"
        f"&response_type=code"
        f"&redirect_uri={settings.MICROSOFT_REDIRECT_URI}"
        f"&scope=openid User.Read Files.Read offline_access"
        f"&response_mode=query"
    )
    return redirect(auth_url)

# Step 2: Handle Callback & Exchange Code for Token
def microsoft_auth_callback(request):
    code = request.GET.get("code")
    if not code:
        return JsonResponse({"error": "No authorization code received"}, status=400)

    data = {
        "client_id": settings.MICROSOFT_CLIENT_ID,
        "client_secret": settings.MICROSOFT_CLIENT_SECRET,
        "code": code,
        "redirect_uri": settings.MICROSOFT_REDIRECT_URI,
        "grant_type": "authorization_code",
    }

    response = requests.post(settings.MICROSOFT_TOKEN_URL, data=data)
    token_data = response.json()

    if "access_token" not in token_data:
        return JsonResponse({"error": "Failed to get access token", "details": token_data}, status=400)

    # Store tokens in the database
    user = request.user
    user.microsoft_access_token = token_data["access_token"]
    user.microsoft_refresh_token = token_data.get("refresh_token", "")
    expires_in = token_data.get("expires_in", 3600)  # Default expiry to 1 hour if not provided
    user.microsoft_token_expiry = now() + datetime.timedelta(seconds=expires_in)
    user.save()

    return redirect("microsoft_fetch_excel")

# Step 3: Fetch Excel Files from OneDrive
@login_required
def microsoft_fetch_excel(request):
    user = request.user
    access_token = get_valid_microsoft_token(user)

    if not access_token:
        return redirect("microsoft_login")

    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"{settings.GRAPH_API_BASE_URL}/me/drive/root/children"

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return JsonResponse({"error": "Failed to fetch files", "details": response.json()}, status=response.status_code)

    files = response.json().get("value", [])
    excel_files = [
        {"name": f["name"], "download_url": f.get("@microsoft.graph.downloadUrl", "#")}
        for f in files if f["name"].endswith(".xlsx")
    ]

    return render(request, "connectors/microsoft.html", {"files": excel_files})

def get_valid_microsoft_token(user):
    if user.microsoft_access_token and user.microsoft_token_expiry and user.microsoft_token_expiry > now():
        return user.microsoft_access_token

    if not user.microsoft_refresh_token:
        return None  # No valid token available

    # Refresh token request
    data = {
        "client_id": settings.MICROSOFT_CLIENT_ID,
        "client_secret": settings.MICROSOFT_CLIENT_SECRET,
        "refresh_token": user.microsoft_refresh_token,
        "grant_type": "refresh_token",
    }
    response = requests.post(settings.MICROSOFT_TOKEN_URL, data=data)
    token_data = response.json()

    if "access_token" in token_data:
        user.microsoft_access_token = token_data["access_token"]
        user.microsoft_refresh_token = token_data.get("refresh_token", user.microsoft_refresh_token)
        expires_in = token_data.get("expires_in", 3600)
        user.microsoft_token_expiry = now() + datetime.timedelta(seconds=expires_in)
        user.save()
        return token_data["access_token"]

    return None  # Token refresh failed