"""
URL configuration for backend project.

The `urlpatterns` list routes URLs to sub_views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function sub_views
    1. Add an import:  from my_app import sub_views
    2. Add a URL to urlpatterns:  path('', sub_views.home, name='home')
Class-based sub_views
    1. Add an import:  from other_app.sub_views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),  # Django admin
    path('api/', include('connectors.urls')),  # Include URLs from your sheets_connector app
]
