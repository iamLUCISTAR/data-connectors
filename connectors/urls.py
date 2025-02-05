# google_sheets/urls.py

from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    # Google OAuth URLs
    path('google-auth/', views.GoogleAuthView.as_view(), name='google-auth'),
    path('google-sheets/', views.GoogleSheetsView.as_view(), name='google-sheets'),
    path('google/callback/', views.GoogleAuthCallbackView.as_view(), name='google-callback'),
    # User Authentication URLs (Login, Signup)
    path('login/', auth_views.LoginView.as_view(), name='login'),
    path('signup/', views.SignUpView.as_view(), name='signup'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),

    # Home page (protected page, user must be logged in)
    path('', views.HomePageView.as_view(), name='home'),  # Home page for authenticated users
]
