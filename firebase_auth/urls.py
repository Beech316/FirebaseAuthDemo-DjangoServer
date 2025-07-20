from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('verify-token/', views.verify_firebase_token, name='verify_firebase_token'),
    path('register/', views.register_user, name='register_user'),
]
