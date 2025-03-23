from django.urls import path
from django.contrib.auth import views as auth_views
from . import views  # Import your custom views

urlpatterns = [
    # Home Page
    path('', views.homepage, name='homepage'),

    # User Authentication
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('register/', views.register, name='register'),

    # Admin Authentication
    path('admin-login/', views.admin_login, name='admin_login'),

    # Password Reset Flow (Django Built-in Views)
    path('password-reset/', views.CustomPasswordResetView.as_view(), name='password_reset'),
    path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='password_reset_done.html'), name='password_reset_done'),
    path('password-reset-confirm/<uidb64>/<token>/', views.CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('password-reset-complete/', auth_views.PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'), name='password_reset_complete'),

    # Forgot Password (Custom View)
    path('forgot-password/', views.forgot_password, name='forgot_password'),

    # Email Verification
    path('activate/<uidb64>/<token>/', views.activate_account, name='activate_account'),
]
