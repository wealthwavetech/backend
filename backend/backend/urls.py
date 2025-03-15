from django.contrib import admin
from django.urls import path, include
from authapp.views import home, logout_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('authapp.urls')),
    path('', home),
]
