from .models import User
from rest_framework import generics, status
from .serializers import RegisterSerializer, EmailVerificationSerializer, ForgotPasswordSerializer, PasswordResetSerializer, LogoutSerializer
from rest_framework.response import Response
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth import authenticate, logout
from rest_framework import status, permissions
from rest_framework.generics import GenericAPIView
from rest_framework.authtoken.models import Token
from .serializers import LoginSerializer
from django.core.exceptions import ObjectDoesNotExist


    
class RegisterView(generics.GenericAPIView):
    
    serializer_class = RegisterSerializer
    
    def post(self, request):
        user=request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        
        user = User.object.get(email=user_data['email'])
        user_data = serializer.data
        otp = Util.generate_otp(6)
        user.otp = otp
        user.save()
        current_site = get_current_site(request).domain
    
       
        absurl = 'http://'+current_site+'?token='+str(otp)
        email_body = 'Hi '+user.username+' Use link below to verify ypur email \n'+ absurl
        data = {'email_body':email_body, 'to_email':user.email, 'email_subject': 'verify your email'}
        Util.send_email(data)
        
        return Response(user_data, status=status.HTTP_201_CREATED)
    
class VerifyEmail(generics.GenericAPIView):
    serializer_class = EmailVerificationSerializer
    
    def post(self, request):
        data = request.data
        otp = data.get('otp', '')
        email = data.get('email', '')
        if otp is None or email is None:
            return Response(data=dict(invalid_input="Please provide both otp and email"), status=status.HTTP_400_BAD_REQUEST)
        get_user = User.object.filter(email=email)
        if not get_user.exists():
            return Response(data=dict(invalid_email = "please provide a valid registered email"), status=status.HTTP_400_BAD_REQUEST )
        user = get_user[0] 
        if user.otp != otp:
            return Response(data=dict(invalid_otp = "please provide a valid otp code"), status=status.HTTP_400_BAD_REQUEST)
        user.is_verified = True
       
        user.save()
        return Response(data={
                "verified status":"Your account has been successfully verified"
            }, status=status.HTTP_200_OK)
    
class LoginView(GenericAPIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = LoginSerializer
    def post(self, request):
        email = request.data.get('email', '')
        password = request.data.get('password', '')
        if email is None or password is None:
            return Response(data={'invalid_credentials': 'Please provide both email and password'}, status=status.HTTP_400_BAD_REQUEST)
        user = authenticate(username=email, password=password)
        if not user:
            return Response(data={'invalid_credentials': 'Ensure both email and password are correct and you have verify you account'}, status=status.HTTP_400_BAD_REQUEST)
        if not user.is_verified:
            return Response(data={'invalid_credentials': 'Please verify your account'}, status=status.HTTP_400_BAD_REQUEST)
        serializer = self.serializer_class(user)
        token, _ = Token.objects.get_or_create(user=user)
        return Response(data={'token': token.key}, status=status.HTTP_200_OK)
    
class LogoutView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    
    def get(self, request):
        logout(request)
        return Response(status=status.HTTP_200_OK)
    
    
class ForgotPasswordView(generics.GenericAPIView):
    serializer_class = ForgotPasswordSerializer
    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.object.get(email=email)
            
        except ObjectDoesNotExist:
            return Response({"message":"User does not exist"}, status=404)
        OTP=Util.generate_otp(6)
        user.otp = OTP
        email = user.email
        user.save()
        if user.is_active == True:  
            email_body = 'Hi '+user.username+'Here is the Otp code to reset your password \n' + str(OTP)
            data = {'email_body':email_body, 'to_email':user.email, 'email_subject': 'verify your email'}
            Util.send_email(data)
            return Response({
                "message": "success",
                "errors": None
            }, status=200)
            
class PasswordReset(generics.GenericAPIView):
    serializer_class=PasswordResetSerializer
    def put(self, request):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        otp = serializer.data.get('otp')
        password = request.data.get('password')
        confirm_password =request.data.get('confirm_password')
        try:
            user = User.object.get(email=email)
        except ObjectDoesNotExist:
            return Response({"message":"User does not exist"}, status=404)
        if password == confirm_password:
            keygen=user.otp
            OTP=keygen
            if otp != OTP:  
                return Response({
                "message": "Failure",
                "data": None,
                "errors": {
                    'otp_code': "OTP does not match or expired"
                }
            }, status=400)
            user.set_password(password)
            user.save()
            return Response({
                "message": 'success! Password reset successful' ,
                "data": {
                    "otp": None
                },
                "errors": None
            }, status=200)
        else:
            return Response({"message":"Failure","data":None,"errors":{
                "passwords": "The two Passwords must be the same"
            }},status=400)