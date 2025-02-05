# google_sheets/views.py
from datetime import timedelta

from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login, authenticate
from django.utils.timezone import now
from django.views.generic import TemplateView
from django.contrib.auth.decorators import login_required
from googleapiclient.errors import HttpError
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

class HomePageView(TemplateView):
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

class GoogleAuthCallbackView(APIView):
    """Handles Google OAuth callback and saves tokens."""

    def get(self, request):
        auth_code = request.GET.get("code")
        creds = get_google_credentials(auth_code, request)

        user = request.user
        user.google_access_token = creds.token
        user.google_refresh_token = creds.refresh_token

        # Ensure creds.expiry is a datetime object and add a timedelta to current time.
        user.google_token_expiry = creds.expiry
        user.save()

        return redirect('home')  # Redirect to home after successful login

class GoogleSheetsView(APIView):
    """Fetches list of Google Sheets available for the user."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        creds = get_google_credentials(user)

        if not creds:
            return Response({"error": "Google authentication required."}, status=401)

        try:
            service = build("sheets", "v4", credentials=creds)
            sheet_list = []

            results = service.spreadsheets().get(spreadsheetId="your-spreadsheet-id").execute()
            sheets = results.get("sheets", [])
            for sheet in sheets:
                sheet_list.append({
                    "title": sheet["properties"]["title"],
                    "sheet_id": sheet["properties"]["sheetId"]
                })

            return Response({"sheets": sheet_list})

        except HttpError as err:
            return Response({"error": str(err)}, status=400)
