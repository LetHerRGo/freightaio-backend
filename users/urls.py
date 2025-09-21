from django.urls import path
from . import views

urlpatterns = [
    path("me/", views.me),      # protected
    path("ping/", views.ping),  # public
]
