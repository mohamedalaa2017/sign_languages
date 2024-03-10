from rest_framework.views import APIView
from rest_framework import status

from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from .serializers import UserLoginSerializer
from rest_framework.permissions import AllowAny

from .serializers import UserRegistrationSerializer
from django.contrib.auth import get_user_model
from .models import CustomUser

from rest_framework.response import Response
from rest_framework import status
from rest_framework.generics import CreateAPIView
from rest_framework import generics
from rest_framework.parsers import MultiPartParser, FormParser

from django.contrib.auth.models import User
from .serializers import PasswordResetRequestSerializer, PasswordResetSerializer
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode
from django.utils.http import urlsafe_base64_decode

from .serializers import CustomUserSerializer, CustomUserUpdateSerializer
from rest_framework.permissions import IsAuthenticated


from django.core.mail import send_mail
from django.urls import reverse
from django.conf import settings
from rest_framework.generics import GenericAPIView

import random
from .serializers import ConfirmationSerializer

class UserLoginAPIView(APIView):

    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({'token': token.key})

User = get_user_model()

class UserRegistrationAPIView(APIView):
    http_method_names = ['post']
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()  # Use the default manager for user creation
            email = serializer.validated_data.get('email')
            user = User.objects.get(email=email)

            user.verification_code = random.randint(1000, 9999)
            user.save()
            # Create a token for the user
            token, created = Token.objects.get_or_create(user=user)

            return Response({'token': token.key})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




# class PasswordResetRequestAPIView(CreateAPIView):
#     serializer_class = PasswordResetRequestSerializer
#     permission_classes = [AllowAny]

#     def create(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         self.send_reset_verification(serializer)
#         return Response({"detail": "Password reset verification sent successfully"}, status=status.HTTP_200_OK)

#     def send_reset_verification(self, serializer):
#         email = serializer.validated_data['email']
#         try:
#             user = User.objects.get(email=email)
#         except User.DoesNotExist:
#             print(f"User with email {email} not found.")

#         user = User.objects.get(email=email)

#         token_generator = PasswordResetTokenGenerator()
#         uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
#         token = token_generator.make_token(user)

#         # reset_url = reverse('password_reset_confirm_api', kwargs={'uidb64': uidb64, 'token': token})
#         reset_url = f'{uidb64}/{token}'

#         subject = 'Password Reset Verification'
#         message = f'Verification code is: {reset_url}'

#         try:
#             send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])
#         except Exception as e:
#              print(f"Error sending email: {e}")



# class PasswordResetConfirmAPIView(GenericAPIView):
#     permission_classes = [AllowAny]
#     serializer_class = PasswordResetRequestSerializer


#     def get(self, request, *args, **kwargs):
#         validation = self.request.query_params.get('validation')
#         if validation is None:
#             return Response({'error': 'Validation parameter is required'}, status=status.HTTP_400_BAD_REQUEST)

#         try: 
#             uidb64, token = validation.split('/')
#         except Exception as e :
#             return Response({'error': f'{e}'}, status=status.HTTP_400_BAD_REQUEST)

#         return Response({"detail": "the validation is right"}, status=status.HTTP_200_OK)



#     def post(self, request, *args, **kwargs):
#         validation = self.request.query_params.get('validation')
#         if validation is None:
#             return Response({'error': 'Validation parameter is required'}, status=status.HTTP_400_BAD_REQUEST)

#         try: 
#             uidb64, token = validation.split('/')
#         except Exception as e :
#             return Response({'error': f'{e}'}, status=status.HTTP_400_BAD_REQUEST)


#         try:
#             uid = force_str(urlsafe_base64_decode(uidb64))
#             user = User.objects.get(pk=uid)
#         except (TypeError, ValueError, OverflowError, User.DoesNotExist):
#             user = None

#         if user is not None and PasswordResetTokenGenerator().check_token(user, token):
#             serializer = PasswordResetSerializer(data=request.data)
#             serializer.is_valid(raise_exception=True)
#             self.reset_password(user, serializer.validated_data['new_password'])
#             return Response({"detail": "Password reset successfully"}, status=status.HTTP_200_OK)

#         return Response({"detail": "Invalid reset link or token"}, status=status.HTTP_400_BAD_REQUEST)

#     def reset_password(self, user, new_password):
#         user.set_password(new_password)
#         user.save()




class PasswordResetRequestAPIView(CreateAPIView):
     serializer_class = PasswordResetRequestSerializer
     permission_classes = [AllowAny]

     def create(self, request, *args, **kwargs):
         serializer = self.get_serializer(data=request.data)
         serializer.is_valid(raise_exception=True)
         self.send_reset_verification(serializer)
         return Response({"detail": "Password reset verification sent successfully"}, status=status.HTTP_200_OK)

     def send_reset_verification(self, serializer):
         email = serializer.validated_data['email']
         try:
             user = User.objects.get(email=email)
         except User.DoesNotExist:
             print(f"User with email {email} not found.")

         user = User.objects.get(email=email)

         user.verification_code = random.randint(1000, 9999)
         

         # reset_url = reverse('password_reset_confirm_api', kwargs={'uidb64': uidb64, 'token': token})
         reset_url = user.verification_code

         subject = 'Password Reset Verification'
         message = f'Verification code is: {reset_url}'

         try:
             send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])
         except Exception as e:
              print(f"Error sending email: {e}")

         user.save()




class ConfirmationAPIView(CreateAPIView):
    serializer_class = ConfirmationSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            verification_code = serializer.validated_data['verification_code']

            user = get_user_model().objects.filter(email=email, verification_code=verification_code).first()

            if user:
                if 'new_password' in serializer.validated_data:
                    new_password = serializer.validated_data['new_password']
                    print(new_password)
                    user.set_password(new_password)
                    user.save()
                    return Response({'detail': 'password changed successfully.'}, status=status.HTTP_200_OK)
                return Response({'detail': 'Verification code is right.'}, status=status.HTTP_200_OK)
            
            else:
                return Response({'error': 'Invalid verification code.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'error': 'Invalid data.'}, status=status.HTTP_400_BAD_REQUEST)





# class PasswordResetConfirmAPIView(GenericAPIView):
#     permission_classes = [AllowAny]
#     serializer_class = PasswordResetRequestSerializer


#     def get(self, request, *args, **kwargs):
#         validation = self.request.query_params.get('validation')
#         if validation is None:
#             return Response({'error': 'Validation parameter is required'}, status=status.HTTP_400_BAD_REQUEST)

#         try: 
#             uidb64, token = validation.split('/')
#         except Exception as e :
#             return Response({'error': f'{e}'}, status=status.HTTP_400_BAD_REQUEST)

#         return Response({"detail": "the validation is right"}, status=status.HTTP_200_OK)



#     def post(self, request, *args, **kwargs):
#         validation = self.request.query_params.get('validation')
#         if validation is None:
#             return Response({'error': 'Validation parameter is required'}, status=status.HTTP_400_BAD_REQUEST)

#         try: 
#             uidb64, token = validation.split('/')
#         except Exception as e :
#             return Response({'error': f'{e}'}, status=status.HTTP_400_BAD_REQUEST)


#         try:
#             uid = force_str(urlsafe_base64_decode(uidb64))
#             user = User.objects.get(pk=uid)
#         except (TypeError, ValueError, OverflowError, User.DoesNotExist):
#             user = None

#         if user is not None and PasswordResetTokenGenerator().check_token(user, token):
#             serializer = PasswordResetSerializer(data=request.data)
#             serializer.is_valid(raise_exception=True)
#             self.reset_password(user, serializer.validated_data['new_password'])
#             return Response({"detail": "Password reset successfully"}, status=status.HTTP_200_OK)

#         return Response({"detail": "Invalid reset link or token"}, status=status.HTTP_400_BAD_REQUEST)

#     def reset_password(self, user, new_password):
#         user.set_password(new_password)
#         user.save()


from rest_framework.exceptions import AuthenticationFailed

class CustomUserDetailView(generics.RetrieveAPIView):
    serializer_class = CustomUserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user
    
    def handle_exception(self, exc):
        if isinstance(exc, AuthenticationFailed):
            return Response({"error": str(exc)}, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)


class CustomUserUpdateView(generics.UpdateAPIView):
    serializer_class = CustomUserUpdateSerializer
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user
    
    def handle_exception(self, exc):
        if isinstance(exc, AuthenticationFailed):
            return Response({"error": str(exc)}, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)