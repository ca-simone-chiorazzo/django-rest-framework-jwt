from demo.authentication.custom_issuer_authentication import CustomJSONWebTokenAuthentication
from rest_framework_jwt.serializers import JSONWebTokenSerializer, VerifyAuthTokenSerializer, RefreshAuthTokenSerializer


class CustomJSONWebTokenSerializer(JSONWebTokenSerializer):
    _jwt_auth_class = CustomJSONWebTokenAuthentication


class CustomVerifyAuthTokenSerializer(VerifyAuthTokenSerializer):
    _jwt_auth_class = CustomJSONWebTokenAuthentication


class CustomRefreshAuthTokenSerializer(RefreshAuthTokenSerializer):
    _jwt_auth_class = CustomJSONWebTokenAuthentication
