from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('register/', views.register_user, name='register_user'),
    path('verify-token/', views.verify_firebase_token, name='verify_firebase_token'),
    path('check-email-verification/', views.check_email_verification, name='check_email_verification'),
    path('resend-verification-email/', views.resend_verification_email, name='resend_verification_email'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('profile/', views.user_profile, name='user_profile'),
    path('delete-account/', views.delete_account, name='delete_account'),
]
