from . import views


from django.urls import path
# from .views import  PasswordResetConfirmAPIView, PasswordResetRequestAPIView
from .views import PasswordResetRequestAPIView,  ConfirmationAPIView

# from .views import RegisterView 

# from rest_auth.views import PasswordResetConfirmView
# LoginView

urlpatterns = [
    path('register/', views.UserRegistrationAPIView.as_view(), name='user-register'),
    path('login/', views.UserLoginAPIView.as_view(), name='user-login'),

    path('password-reset/request/', PasswordResetRequestAPIView.as_view(), name='password_reset_request_api'),
    # path('password-reset/confirm/<str:uidb64>/<str:token>/', PasswordResetConfirmAPIView.as_view(), name='password_reset_confirm_api'),
    
    
    # path('password-reset/confirm/', PasswordResetConfirmAPIView.as_view(), name='password_reset_confirm_api'),
    path('password-reset/confirm/', ConfirmationAPIView.as_view(), name='password_reset_confirm_api'),

    # path('login/', views.CustomObtainAuthToken.as_view(), name='login'),


    # path("guest", views.GuestListView.as_view()),
]
