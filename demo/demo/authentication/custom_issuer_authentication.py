from rest_framework_jwt.authentication import JSONWebTokenAuthentication


class CustomJSONWebTokenAuthentication(JSONWebTokenAuthentication):
    issuer_code = 'custom-issuer'
