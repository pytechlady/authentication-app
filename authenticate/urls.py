from django.urls import path
from .views import RegisterView, VerifyEmail, LoginView, LogoutView, ForgotPasswordView, PasswordReset


urlpatterns = [
   path('register', RegisterView.as_view(), name = 'register'),
   path('email-verify', VerifyEmail.as_view(), name = 'email-verify'),
   path('login', LoginView.as_view(), name='login'),
   path('logout', LogoutView.as_view(), name='logout'),
   path('forgot-password', ForgotPasswordView.as_view(), name ='forgot-password'),
   path('reset-password', PasswordReset.as_view(), name='reset-password')
]