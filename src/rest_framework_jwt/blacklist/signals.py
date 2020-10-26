# -*- coding: utf-8 -*-

from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import BlacklistedToken
from ..multi_issuer_api_settings import DEFAULT_ISSUER_CODE
from ..settings import api_settings
from ..utils import jwt_get_issuer


@receiver(post_save, sender=BlacklistedToken)
def delete_stale_tokens(instance, **kwargs):
    issuer = jwt_get_issuer(instance.token)
    issuer = issuer or DEFAULT_ISSUER_CODE
    issuer_settings = api_settings.get_issuer_settings(issuer)
    if issuer_settings.JWT_DELETE_STALE_BLACKLISTED_TOKENS:
        BlacklistedToken.objects.delete_stale_tokens()
