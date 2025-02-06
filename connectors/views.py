# google_sheets/views.py
from datetime import timedelta
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
            return redirect('home')  # Redirect to the home page after signup
        return render(request, self.template_name, {'form': form})


class HomePageView(LoginRequiredMixin, TemplateView):
    template_name = 'connectors/home.html'

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

class GoogleAuthCallbackView(APIView):
    """Handles Google OAuth callback and saves tokens."""

    def get(self, request):
        auth_code = request.GET.get("code")

        # Use the auth code to get credentials
        creds = get_google_credentials(auth_code, request)

        if creds is None:
            messages.error(request, "Google authentication failed. Please try again.")
            return redirect('home')

        user = request.user
        creds.refresh(Request())
        user.google_access_token = creds.token
        user.google_refresh_token = creds.refresh_token
        user.google_token_expiry = timezone.make_aware(creds.expiry)
        user.save()

        # Store a success message in the session
        messages.success(request, "Successfully authenticated with Google!")

        return redirect('home')


class GoogleSheetsView(APIView):
    """Fetches list of Google Sheets available for the user."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        # Ensure the user has stored tokens
        if not user.google_access_token or not user.google_refresh_token or not user.google_token_expiry:
            return Response({"error": "Google authentication required."}, status=401)

        # Refresh token logic (if token expired)
        if user.google_token_expiry <= now():
            return Response({"error": "Google token expired. Please re-authenticate."}, status=401)

        # Load credentials from user model
        creds = Credentials(
            token=user.google_access_token,
            refresh_token=user.google_refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=settings.GOOGLE_OAUTH_CLIENT_ID,
            client_secret=settings.GOOGLE_OAUTH_CLIENT_SECRET
        )

        try:
            service = build("drive", "v3", credentials=creds)  # Use Google Drive API to list files
            sheet_list = []

            # List all files (including spreadsheets) in the user's Google Drive
            results = service.files().list(q="mimeType='application/vnd.google-apps.spreadsheet'",
                                           fields="files(id, name)").execute()
            files = results.get("files", [])

            for file in files:
                sheet_list.append({
                    "sheet_id": file["id"],
                    "title": file["name"]
                })

            return Response({"sheets": sheet_list})

        except HttpError as err:
            return Response({"error": str(err)}, status=400)


class GoogleSheetDataView(APIView):
    """Fetches data from the selected Google Sheet."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Get the selected spreadsheet_id from the query params
        spreadsheet_id = request.GET.get("spreadsheet_id")

        # Ensure the user has stored tokens
        user = request.user
        if not user.google_access_token or not user.google_refresh_token or not user.google_token_expiry:
            return Response({"error": "Google authentication required."}, status=401)

        # Refresh token logic (if token expired)
        if user.google_token_expiry <= now():
            return Response({"error": "Google token expired. Please re-authenticate."}, status=401)

        # Load credentials from user model
        creds = Credentials(
            token=user.google_access_token,
            refresh_token=user.google_refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=settings.GOOGLE_OAUTH_CLIENT_ID,
            client_secret=settings.GOOGLE_OAUTH_CLIENT_SECRET
        )

        try:
            # Build the Sheets API service
            sheets_service = build("sheets", "v4", credentials=creds)

            # Fetch data from the specified Google Sheet
            range_ = "Sheet1"  # You can modify this if you want specific range like "Sheet1!A1:Z100"
            result = sheets_service.spreadsheets().values().get(
                spreadsheetId=spreadsheet_id, range=range_
            ).execute()
            rows = result.get("values", [])

            # If the sheet is empty
            if not rows:
                return Response({"message": "No data found in the selected sheet."})

            # Return the rows in the sheet
            return Response({"data": rows})

        except HttpError as err:
            return Response({"error": str(err)}, status=400)