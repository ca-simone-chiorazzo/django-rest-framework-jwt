# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from datetime import datetime
import sys

from django import VERSION

from .multi_issuer_api_settings import DEFAULT_ISSUER_CODE
from .settings import api_settings


try:
    from django.urls import include
except ImportError:
    from django.conf.urls import include  # noqa: F401


try:
  from django.conf.urls import url
except ImportError:
  from django.urls import url


if sys.version_info[0] == 2:
    # Use unicode-aware gettext on Python 2
    from django.utils.translation import ugettext_lazy as gettext_lazy
else:
    from django.utils.translation import gettext_lazy as gettext_lazy


try:
    from django.utils.encoding import smart_str
except ImportError:
    from django.utils.encoding import smart_text as smart_str


def has_set_cookie_samesite():
    return (VERSION >= (2,1,0))


def set_cookie_with_token(response, name, token, issuer_code=DEFAULT_ISSUER_CODE):
    issuer_settings = api_settings.get_issuer_settings(issuer_code)
    params = {
        'expires': datetime.utcnow() + issuer_settings.JWT_EXPIRATION_DELTA,
        'domain': issuer_settings.JWT_AUTH_COOKIE_DOMAIN,
        'path': issuer_settings.JWT_AUTH_COOKIE_PATH,
        'secure': issuer_settings.JWT_AUTH_COOKIE_SECURE,
        'httponly': True
    }

    if has_set_cookie_samesite():
        params.update({'samesite': issuer_settings.JWT_AUTH_COOKIE_SAMESITE})

    response.set_cookie(name, token, **params)
