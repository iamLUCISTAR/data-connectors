# google_sheets/urls.py

from django.urls import path
from .sub_views import google, microsoft
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    # Google OAuth URLs
    path('google/login/', google.google_login, name='google-login'),
    path('google/callback/', google.google_auth_callback, name='google-callback'),
    path('google/sheets/', google.google_fetch_sheets, name='google-sheets'),
    path('google/sheet-data/', google.GoogleSheetDataView.as_view(), name='google-sheet-data'),

    path("microsoft-auth/login/", microsoft.microsoft_login, name="microsoft_login"),
    path("microsoft-auth/callback/", microsoft.microsoft_auth_callback, name="microsoft_auth_callback"),
    path("microsoft-auth/excel-files/", microsoft.microsoft_fetch_excel, name="microsoft_fetch_excel"),

    # User Authentication URLs (Login, Signup)
    path('login/', auth_views.LoginView.as_view(), name='login'),
    path('signup/', views.SignUpView.as_view(), name='signup'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),

    # Home page (protected page, user must be logged in)
    path('', views.LandingPageView.as_view(), name='landing'),  # Home page for authenticated users
    path('google/', views.GooglePageView.as_view(), name='google'),  # Home page for authenticated users
    path('microsoft/', views.MicrosoftPageView.as_view(), name='microsoft'),  # Home page for authenticated users
]
