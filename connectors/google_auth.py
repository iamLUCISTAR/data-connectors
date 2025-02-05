from google_auth_oauthlib.flow import Flow
from django.conf import settings

GOOGLE_SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets.readonly",
    "https://www.googleapis.com/auth/drive.metadata.readonly"
]

def get_google_auth_url(request):
    """Generates Google OAuth authentication URL."""
    flow = Flow.from_client_secrets_file(
        settings.GOOGLE_OAUTH_CREDENTIALS,
        scopes=GOOGLE_SCOPES,
        redirect_uri=request.build_absolute_uri("/api/google/callback/")
    )
    auth_url, _ = flow.authorization_url(prompt="consent")
    return auth_url

def get_google_credentials(auth_code, request):
    """Fetches OAuth credentials using the authorization code."""
    flow = Flow.from_client_secrets_file(
        settings.GOOGLE_OAUTH_CREDENTIALS,
        scopes=GOOGLE_SCOPES,
        redirect_uri=request.build_absolute_uri("/api/google/callback/")
    )
    flow.fetch_token(code=auth_code)
    return flow.credentials
