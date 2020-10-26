# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from rest_framework.response import Response
from rest_framework.views import APIView

from app.serializers import (
    CustomJSONWebTokenSerializer, CustomVerifyAuthTokenSerializer,
    CustomRefreshAuthTokenSerializer,
)
from demo.authentication.custom_issuer_authentication import CustomJSONWebTokenAuthentication
from rest_framework_jwt.blacklist.permissions import IsNotBlacklisted
from rest_framework_jwt.permissions import IsSuperUser
from rest_framework_jwt.views import ObtainJSONWebTokenView, VerifyJSONWebTokenView, RefreshJSONWebTokenView


class TestView(APIView):
    def get(self, request):
        return Response({'foo': 'bar'})


class SuperuserTestView(APIView):
    permission_classes = (IsSuperUser, )

    def get(self, request):
        return Response({'foo': 'bar'})


class BlacklistPermissionTestView(APIView):
    permission_classes = (IsNotBlacklisted, )

    def get(self, request):
        return Response({'foo': 'bar'})


class CustomObtainJSONWebTokenView(ObtainJSONWebTokenView):
    _jwt_auth_class = CustomJSONWebTokenAuthentication
    serializer_class = CustomJSONWebTokenSerializer


class CustomVerifyJSONWebTokenView(VerifyJSONWebTokenView):
    _jwt_auth_class = CustomJSONWebTokenAuthentication
    serializer_class = CustomVerifyAuthTokenSerializer


class CustomRefreshJSONWebTokenView(RefreshJSONWebTokenView):
    _jwt_auth_class = CustomJSONWebTokenAuthentication
    serializer_class = CustomRefreshAuthTokenSerializer


test_view = TestView.as_view()
superuser_test_view = SuperuserTestView.as_view()
blacklist_test_view = BlacklistPermissionTestView.as_view()

obtain_jwt_token_custom_issuer = CustomObtainJSONWebTokenView.as_view()
verify_jwt_token_custom_issuer = CustomVerifyJSONWebTokenView.as_view()
refresh_jwt_token_custom_issuer = CustomRefreshJSONWebTokenView.as_view()
