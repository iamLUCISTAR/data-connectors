import datetime

from django.conf import settings
from django.utils.timezone import now
from django.contrib.auth.decorators import login_required
import requests
from django.shortcuts import redirect, render
from django.http import JsonResponse


def microsoft_login(request):
    if request.user.microsoft_access_token:
        return redirect(
            "microsoft_fetch_excel")

    auth_url = (
        f"{settings.MICROSOFT_AUTH_URL}?"
        f"client_id={settings.MICROSOFT_CLIENT_ID}"
        f"&response_type=code"
        f"&redirect_uri={settings.MICROSOFT_REDIRECT_URI}"
        f"&scope=openid User.Read Files.Read offline_access"
        f"&response_mode=query"
    )
    return redirect(auth_url)

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

    user = request.user
    user.microsoft_access_token = token_data["access_token"]
    user.microsoft_refresh_token = token_data.get("refresh_token", "")
    expires_in = token_data.get("expires_in", 3600)  # Default expiry to 1 hour if not provided
    user.microsoft_token_expiry = now() + datetime.timedelta(seconds=expires_in)
    user.save()

    return redirect("microsoft_fetch_excel")

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
        return None

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

    return None