from django.shortcuts import render
from django.core.exceptions import ObjectDoesNotExist
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
import datetime
from rest_framework.exceptions import ValidationError, NotFound
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.exceptions import TokenError

from .serializers import SignUpSerializer, ChangeUserInformation, ChangeUserPhotoSerializer, LoginSerializer, \
    LoginRefreshSerializer, LogoutSerializer, ForgotPasswordSerializer, ResetPasswordSerializer
from .models import User, NEW, CODE_VERIFIED, VIA_EMAIL, VIA_PHONE
from shared.utility import send_email, check_email_or_phone


class SignUpView(generics.CreateAPIView):
    permission_classes = [AllowAny, ]
    queryset = User.objects.all()
    serializer_class = SignUpSerializer


class VerifyAPIView(APIView):
    permission_classes = [IsAuthenticated, ]

    def post(self, request, *args, **kwargs):
        user = self.request.user
        code = self.request.data.get('code')

        self.check_verify(user, code)
        return Response(
            {
                "SUCCESS": True,
                "auth_status": user.auth_status,
                "access": user.token()['access'],
                "refresh": user.token()['refresh_token']
            }
        )

    @staticmethod
    def check_verify(user, code):
        verifies = user.verify_codes.filter(expiration_time__gte=datetime.datetime.now(), code=code, is_confirmed=False)
        if not verifies.exists():
            data = {
                "Message": "Tasdiqlash parolingiz noto'g'ri yoki eskirgan"
            }
            raise ValidationError(data)
        else:
            verifies.update(is_confirmed=True)

        if user.auth_status == NEW:
            user.auth_status = CODE_VERIFIED
            user.save()
        return True


class GetNewVerification(APIView):
    permission_classes = [IsAuthenticated, ]

    def get(self, request, *args, **kwargs):
        user = self.request.user
        self.check_verification(user)
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_email(user.email, code)
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            send_email(user.phone_number, code)
        else:
            data = {
                "Message": "Email yoki telefon raqam noto'g'ri kiritildi"
            }
            raise ValidationError(data)
        return Response(
            {
                "Success": True,
                "Message": "Tasdiqlash kodingiz qaytadan yuborildi."
            }
        )

    @staticmethod
    def check_verification(user):
        verifies = user.verify_codes.filter(expiration_time__gte=datetime.datetime.now(), is_confirmed=False)
        if verifies.exists():
            data = {
                "Message": "Kodingiz ishlatish uchun yaroqli. Biroz kuting"
            }
            raise ValidationError(data)


class ChangeUserAPIView(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated, ]
    serializer_class = ChangeUserInformation
    http_method_names = ['put', 'patch']

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        super(ChangeUserAPIView, self).update(request, *args, **kwargs)
        data = {
            "success": True,
            "Message": "Muvaffaqiyatli yangilandi",
            "Auth_status": self.request.user.auth_status,
        }
        return Response(data, status=200)


class ChangeUserPhotoView(APIView):
    permission_classes = [IsAuthenticated, ]

    def put(self, request, *args, **kwargs):
        serializer = ChangeUserPhotoSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            serializer.update(user, serializer.validated_data)
            return Response(
                {
                    "Success": True,
                    "Message": "Rasm yangilandi"
                }
            )
        return Response(
            serializer.errors, status=400
        )


class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer


class LoginRefreshView(TokenRefreshView):
    serializer_class = LoginRefreshSerializer


class LogOutView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated, ]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        try:
            refresh_token = self.request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()
            data = (
                {
                    'success': True,
                    'message': 'You are logged out'
                }
            )
            return Response(data, status=205)
        except TokenError:
            return Response(status=400)


class ForgotPasswordView(APIView):
    permission_classes = [AllowAny, ]
    serializer_class = ForgotPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = ForgotPasswordSerializer(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        email_or_phone = serializer.validated_data.get('email_or_phone')
        user = serializer.validated_data.get('user')
        if check_email_or_phone(email_or_phone) == 'email':
            code = user.create_verify_code(VIA_EMAIL)
            send_email(email_or_phone, code)
        elif check_email_or_phone(email_or_phone) == 'phone':
            code = user.create_verify_code(VIA_PHONE)
            send_email(email_or_phone, code)
        return Response(
            {
                'success': True,
                'message': 'Tasdiqlash paroli yuborildi',
                'access': user.token()['access'],
                'refresh': user.token()['refresh'],
                'user_status': user.auth_status
            }, status=200
        )


class ResetPasswordView(APIView):
    permission_classes = [IsAuthenticated, ]
    serializer_class = ResetPasswordSerializer
    http_method_names = ['put', 'patch']

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        response = super(ResetPasswordView, self).update(request, *args, **kwargs)
        try:
            user = User.objects.get(id=response.data.get('id'))
        except ObjectDoesNotExist as e:
            raise NotFound('User not found')

        return Response(
            {
                'success': True,
                'message': 'Parol o\'zgartirildi',
                'access': user.token()['access'],
                'refresh': user.token()['refresh']
            }
        )
