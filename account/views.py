from rest_framework import status
from .models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import (UserRegistrationSerializer, 
                          UserLoginSerializer, UserProfileSerializer, 
                          UserChangePasswordSerializer, 
                          SendPasswordResetEmailSerializer,
                          UserPasswordResetSerializer
        
)
from django.contrib.auth import authenticate
from .renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .utils import Util

#generate token manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class UserRegistrationView(APIView):
    renderer_classes=[UserRenderer]
    def post(self, request,format=None):
        serializer=UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user=serializer.save()
        uid=urlsafe_base64_encode(force_bytes(user.id))
        token=PasswordResetTokenGenerator().make_token(user)
        link=f'https://authapi-8ifr.onrender.com/api/user/activate/{uid}/{token}'
        data={
            'subject':'Activate your account',
            'body': f'Click the following link to activate your.\n{link}',
            'to_email': user.email,
        }
        Util.send_email(data)
        # token=get_tokens_for_user(user)
        return Response({'msg':'We have sent you an verification email to your email address. Please verify it to use your account.'}, status=status.HTTP_201_CREATED)

class UserLoginView(APIView):
    renderer_classes=[UserRenderer]
    def post(self, request):
        serializer=UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email=serializer.data.get('email')
        password=serializer.data.get('password')
        user=authenticate(email=email, password=password)
        if user is not None:
            token=get_tokens_for_user(user)
            return Response({'token':token,'msg':'Login Success'}, status=status.HTTP_200_OK)
        else:
            return Response({'errors':{'non_field_errors':['Email or Password is not valid']}}, status=status.HTTP_404_NOT_FOUND)


class UserProfileView(APIView):
    renderer_classes=[UserRenderer]
    permission_classes=[IsAuthenticated]
    def get(self, request, format=None):
        serializer=UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    
class UserChangePasswordView(APIView):
    renderer_classes=[UserRenderer]
    permission_classes=[IsAuthenticated]
    def post(self, request, format=None):
        serializer= UserChangePasswordSerializer(data=request.data, context={'user':request.user})
        serializer.is_valid(raise_exception=True)
        return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)


class SendPasswordResetEmailView(APIView):
    renderer_classes=[UserRenderer]
    def post(self, request, format=None):
        serializer=SendPasswordResetEmailSerializer(data=request.data)

        serializer.is_valid(raise_exception=True)
        return Response({'msg':f'Password Reset Link Has Been Sent To Your Mail {request.data.get("email")}. Please Check Your Mail.'}, status=status.HTTP_200_OK)
    
class UserPasswordResetView(APIView):
    renderer_classes=[UserRenderer]
    def post(self, request, uid, token, format=None):
        serializer=UserPasswordResetSerializer(data=request.data, context={
            'uid':uid, 'token':token
        })
        serializer.is_valid(raise_exception=True)
        return Response({'msg':'Password reset successfully.'}, status=status.HTTP_200_OK)

class UserAccountActivateView(APIView):
    renderer_classes=[UserRenderer]
    def get(self, request, uid, token, format=None):
        try:
            id=smart_str(urlsafe_base64_decode(uid))
            if User.objects.filter(id=id).exists():
                user=User.objects.get(id=id)
                if PasswordResetTokenGenerator().check_token(user, token):
                    user.is_active=True
                    user.save()
                    return Response({'msg':'Your account is activated. Login to your account to view your token details.'}, status=status.HTTP_200_OK)
                else:
                    return Response({"msg":"Token is not valid or expired."}, status=status.HTTP_404_NOT_FOUND)
            else:
                return Response({"msg":"Token is not valid or expired."},status=status.HTTP_404_NOT_FOUND)
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            return Response({"msg":"Token is not valid or expired."}, status=status.HTTP_404_NOT_FOUND)