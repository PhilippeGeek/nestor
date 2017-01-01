import json

from django import shortcuts


# Create your views here.
from django.contrib.auth import backends
from django.contrib.auth import login
from django.views import View

from account import models


class OAuthLogin(View):
    http_method_names = ['get']

    # noinspection PyMethodMayBeStatic
    def get(self, request, provider):
        service = shortcuts.get_object_or_404(models.OAuthService, name=provider)
        return shortcuts.redirect(service.provider.authorization_url)


class OAuthCallback(View):
    http_method_names = ['get']

    # noinspection PyMethodMayBeStatic
    def get(self, request, provider):
        oauth_service = shortcuts.get_object_or_404(models.OAuthService, name=provider)
        service = oauth_service.provider
        code = request.GET.get('code', None)
        if code is None:
            return shortcuts.redirect('/')
        token = service.retrieve_token(code)
        user = service.login_with_token(token['access_token'], oauth_service)
        if user is not None:
            login(request, user)
        return shortcuts.redirect('/')
