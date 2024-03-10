from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from .models import CustomUser


class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['email', 'first_name', 'last_name', 'profile_image']


class CustomUserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'profile_image']



class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        user = authenticate(email=email, password=password)

        if user and user.is_active:
            data['user'] = user
        else:
            raise serializers.ValidationError("Incorrect email or password")

        return data
    
class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ['email', 'password', 'first_name', 'last_name']
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
            'password': {'write_only': True}
        }
    def create(self, validated_data):
        user = get_user_model().objects.create_user(
            
            first_name = validated_data['first_name'],
            last_name = validated_data['last_name'],
            email=validated_data['email'],
            password=validated_data['password'],
        )
        return user
    
    def save(self, *args, **kwargs):
        # Do not save the username field
        self.username = None
        super().save(*args, **kwargs)



# serializers.py
from rest_framework import serializers

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

# class PasswordResetSerializer(serializers.Serializer):
#     new_password1 = serializers.CharField(write_only=True)
#     new_password2 = serializers.CharField(write_only=True)
    
class PasswordResetSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True)




class ConfirmationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    verification_code = serializers.CharField(max_length=4)
    new_password = serializers.CharField(max_length=255, required=False)
