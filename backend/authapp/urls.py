from django.urls import path
from .views import signup, login, logout_view

urlpatterns = [
    path('signup/', signup, name='signup'),
    path('login/', login, name='login'),
    path('logout/', logout_view, name='logout'),
]
