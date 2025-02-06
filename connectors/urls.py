# google_sheets/urls.py

from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    # Google OAuth URLs
    path('google-auth/', views.GoogleAuthView.as_view(), name='google-auth'),
    path('google-sheets/', views.GoogleSheetsView.as_view(), name='google-sheets'),
    path('google/callback/', views.GoogleAuthCallbackView.as_view(), name='google-callback'),
    path('google-sheet-data/', views.GoogleSheetDataView.as_view(), name='google-sheet-data'),

    # User Authentication URLs (Login, Signup)
    path('login/', auth_views.LoginView.as_view(), name='login'),
    path('signup/', views.SignUpView.as_view(), name='signup'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),

    # Home page (protected page, user must be logged in)
    path('', views.LandingPageView.as_view(), name='landing'),  # Home page for authenticated users
    path('google/', views.GooglePageView.as_view(), name='google'),  # Home page for authenticated users
]
