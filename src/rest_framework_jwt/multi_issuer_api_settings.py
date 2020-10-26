from rest_framework.settings import APISettings


DEFAULT_ISSUER_CODE = 'default'


class MultiIssuerAPISettings(object):
    """ Class that acts as a registry of multi-issuer settings. """

    def __init__(self):
        self._registry = {}

    def add_issuer_settings(self, issuer_id, user_settings, defaults, import_from_strings):
        if issuer_id not in self._registry:
            self._registry[issuer_id] = APISettings(user_settings, defaults, import_from_strings)

    def get_issuer_settings_registry(self):
        return self._registry

    def get_issuer_settings(self, issuer_code):
        return self._registry[issuer_code]

    def __getattr__(self, item):
        """ Backwards compatible method with the standard APISetting """
        if item == '_registry':
            return self._registry
        return self._registry[DEFAULT_ISSUER_CODE].__getattr__(item)

    def __setattr__(self, key, value):
        """ Backwards compatible method with the standard APISetting """

        if key == '_registry':
            super(MultiIssuerAPISettings, self).__setattr__(key, value)
            return

        setattr(self._registry[DEFAULT_ISSUER_CODE], key, value)
