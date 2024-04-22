from django.urls import path
from accounts.views import SignupView, LoginView, LogoutView, ActivationView, RequestResetEmailView, SetNewPasswordView
urlpatterns = [
    path('signup/', SignupView, name='signup'),
    path('login/', LoginView, name='login'),
    path('logout/', LogoutView, name='logout'),
    path('activate/<str:uidb64>/<str:token>/', ActivationView, name='activate'),
    path('request_reset_email/', RequestResetEmailView, name='request_reset_email'),
    path('set_new_password/<uidb64>/<token>/', SetNewPasswordView, name='set_new_password'),
]   


