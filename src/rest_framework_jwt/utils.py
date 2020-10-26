# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import uuid
from calendar import timegm
from datetime import datetime

import jwt
from django.apps import apps
from django.contrib.auth import get_user_model
from django.utils.encoding import force_str
from rest_framework import serializers
from rest_framework.utils.encoders import JSONEncoder

from rest_framework_jwt.compat import gettext_lazy as _
from rest_framework_jwt.multi_issuer_api_settings import DEFAULT_ISSUER_CODE
from rest_framework_jwt.settings import api_settings


def unix_epoch(datetime_object=None):
    """Get unix epoch from datetime object."""

    if not datetime_object:
        datetime_object = datetime.utcnow()
    return timegm(datetime_object.utctimetuple())


def get_username_field():
    return get_user_model().USERNAME_FIELD


def jwt_get_issuer(token):
    payload = jwt.decode(token, None, False)
    if payload:
        return payload.get('iss')


def jwt_get_secret_key(payload=None, issuer_code=DEFAULT_ISSUER_CODE):
    """
    For enhanced security you may want to use a secret key based on user.

    This way you have an option to logout only this user if:
        - token is compromised
        - password is changed
        - etc.
    """
    issuer_settings = api_settings.get_issuer_settings(issuer_code)
    if issuer_settings.JWT_GET_USER_SECRET_KEY:
        username = issuer_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER(payload)
        User = get_user_model()
        
        # Make sure user exists
        try:
            user = User.objects.get_by_natural_key(username)
        except User.DoesNotExist:
            msg = _("User doesn't exist.")
            raise serializers.ValidationError(msg)
        
        key = issuer_settings.JWT_GET_USER_SECRET_KEY(user)
        return key
    return issuer_settings.JWT_SECRET_KEY


def jwt_create_payload(user, issuer_code=DEFAULT_ISSUER_CODE):
    """
    Create JWT claims token.

    To be more standards-compliant please refer to the official JWT standards
    specification: https://tools.ietf.org/html/rfc7519#section-4.1
    """
    issuer_settings = api_settings.get_issuer_settings(issuer_code)
    issued_at_time = datetime.utcnow()
    expiration_time = issued_at_time + issuer_settings.JWT_EXPIRATION_DELTA

    payload = {
        'username': user.get_username(),
        'iat': unix_epoch(issued_at_time),
        'exp': expiration_time
    }

    if issuer_settings.JWT_TOKEN_ID != 'off':
        payload['jti'] = uuid.uuid4()

    if issuer_settings.JWT_PAYLOAD_INCLUDE_USER_ID:
        payload['user_id'] = user.pk

    # It's common practice to have user object attached to profile objects.
    # If you have some other implementation feel free to create your own
    # `jwt_create_payload` method with custom payload.
    if hasattr(user, 'profile'):
        payload['user_profile_id'] = user.profile.pk if user.profile else None,

    # Include original issued at time for a brand new token
    # to allow token refresh
    if issuer_settings.JWT_ALLOW_REFRESH:
        payload['orig_iat'] = unix_epoch(issued_at_time)

    if issuer_settings.JWT_AUDIENCE is not None:
        payload['aud'] = issuer_settings.JWT_AUDIENCE

    if issuer_settings.JWT_ISSUER is not None:
        payload['iss'] = issuer_settings.JWT_ISSUER

    return payload


def jwt_get_username_from_payload_handler(payload):
    """
    Override this function if username is formatted differently in payload
    """

    return payload.get('username')


def jwt_encode_payload(payload, issuer_code=DEFAULT_ISSUER_CODE):
    """Encode JWT token claims."""
    issuer_settings = api_settings.get_issuer_settings(issuer_code)
    headers = None

    signing_algorithm = issuer_settings.JWT_ALGORITHM
    if isinstance(signing_algorithm,list):
        signing_algorithm = signing_algorithm[0]
    if signing_algorithm.startswith("HS"):
        key = jwt_get_secret_key(payload, issuer_code=issuer_code)
    else:
        key = issuer_settings.JWT_PRIVATE_KEY

    if isinstance(key, dict):
        kid, key = next(iter(key.items()))
        headers = {"kid": kid}
    elif isinstance(key,list):
        key = key[0]

    return jwt.encode(payload, key, signing_algorithm, headers=headers, json_encoder=JSONEncoder).decode()


def jwt_decode_token(token, issuer_code=DEFAULT_ISSUER_CODE):
    """Decode JWT token claims."""
    issuer_settings = api_settings.get_issuer_settings(issuer_code)
    options = {
        'verify_exp': issuer_settings.JWT_VERIFY_EXPIRATION,
    }

    algorithms = issuer_settings.JWT_ALGORITHM
    if not isinstance(algorithms, list):
        algorithms = [algorithms]

    hdr = jwt.get_unverified_header(token)
    alg_hdr = hdr["alg"]
    if alg_hdr not in algorithms:
        raise jwt.exceptions.InvalidAlgorithmError

    kid = hdr["kid"] if "kid" in hdr else None

    keys = None
    if alg_hdr.startswith("HS"):
        unverified_payload = jwt.decode(token, None, False)
        keys = jwt_get_secret_key(unverified_payload, issuer_code=issuer_code)
    else:
        keys = issuer_settings.JWT_PUBLIC_KEY

    # if keys are named and the jwt has a kid, only consider exactly that key
    # otherwise if the JWT has no kid, JWT_INSIST_ON_KID selects if we fail
    # or try all defined keys
    if isinstance(keys, dict):
        if kid:
            try:
                keys = keys[kid]
            except KeyError:
                raise jwt.exceptions.InvalidKeyError
        elif issuer_settings.JWT_INSIST_ON_KID:
            raise jwt.exceptions.InvalidKeyError
        else:
            keys = list(keys.values())

    if not isinstance(keys, list):
        keys = [keys]

    ex = None
    for key in keys:
        try:
            return jwt.decode(
                token, key, issuer_settings.JWT_VERIFY, options=options,
                leeway=issuer_settings.JWT_LEEWAY,
                audience=issuer_settings.JWT_AUDIENCE,
                issuer=issuer_settings.JWT_ISSUER, algorithms=[alg_hdr]
            )
        except (jwt.exceptions.InvalidSignatureError) as e:
            ex = e
    raise ex


def jwt_create_response_payload(
        token, user=None, request=None, issued_at=None
):
    """
    Return data ready to be passed to serializer.

    Override this function if you need to include any additional data for
    serializer.

    Note that we are using `pk` field here - this is for forward compatibility
    with drf add-ons that might require `pk` field in order (eg. jsonapi).
    """
    return {'pk': issued_at, 'token': token}


def check_payload(token, jwt_auth_class=None):
    if jwt_auth_class is None:
        from rest_framework_jwt.authentication import JSONWebTokenAuthentication
        jwt_auth_class = JSONWebTokenAuthentication

    if apps.is_installed('rest_framework_jwt.blacklist'):
        from rest_framework_jwt.blacklist.models import BlacklistedToken
        if BlacklistedToken.objects.filter(token=force_str(token)).exists():
            msg = _('Token is blacklisted.')
            raise serializers.ValidationError(msg)

    try:
        payload = jwt_auth_class.jwt_decode_token(token)
    except jwt.ExpiredSignature:
        msg = _('Token has expired.')
        raise serializers.ValidationError(msg)
    except jwt.DecodeError:
        msg = _('Error decoding token.')
        raise serializers.ValidationError(msg)
    except jwt.InvalidTokenError:
        msg = _('Invalid token.')
        raise serializers.ValidationError(msg)

    return payload


def check_user(payload, jwt_auth_class=None):
    if jwt_auth_class is None:
        from rest_framework_jwt.authentication import JSONWebTokenAuthentication
        jwt_auth_class = JSONWebTokenAuthentication

    username = jwt_auth_class. \
        jwt_get_username_from_payload(payload)

    if not username:
        msg = _('Invalid token.')
        raise serializers.ValidationError(msg)

    issuer_settings = api_settings.get_issuer_settings(jwt_auth_class.issuer_code)
    if issuer_settings.JWT_TOKEN_ID == 'require' and not payload.get('jti'):
        msg = _('Invalid token.')
        raise serializers.ValidationError(msg)

    # Make sure user exists
    try:
        User = get_user_model()
        user = User.objects.get_by_natural_key(username)
    except User.DoesNotExist:
        msg = _("User doesn't exist.")
        raise serializers.ValidationError(msg)

    if not user.is_active:
        msg = _('User account is disabled.')
        raise serializers.ValidationError(msg)

    return user
