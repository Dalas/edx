import logging

from django.conf import settings
from social_core.backends.oauth import BaseOAuth2
from social_core.utils import handle_http_errors


class PlecticaOAuth2Backend(BaseOAuth2):
    name = 'plectica-oauth2'
    ID_KEY = 'user_id'

    PROVIDER_URL = settings.FEATURES.get('PLECTICA_OAUTH').get('PROVIDER_URL')
    AUTHORIZATION_URL = '{}/oauth/authorize'.format(PROVIDER_URL)
    ACCESS_TOKEN_URL = '{}/oauth/token'.format(PROVIDER_URL)
    ACCESS_TOKEN_METHOD = 'POST'

    def get_user_details(self, response):
        """ Return user details from SSO account. """
        return response

    @handle_http_errors
    def auth_complete(self, *args, **kwargs):
        """Completes loging process, must return user instance"""

        self.strategy.session_set('{}_state'.format(self.name), self.data.get('state'))
        next_url = '/'
        self.strategy.session.setdefault('next', next_url)
        return super(PlecticaOAuth2Backend, self).auth_complete(*args, **kwargs)


    def user_data(self, access_token, *args, **kwargs):
        """ Grab user profile information from SSO. """
        data = self.get_json(
            '{}/oauth/me'.format(self.PROVIDER_URL),
            params={'access_token': access_token}
        )

        return data

    def pipeline(self, pipeline, pipeline_index=0, *args, **kwargs):
        # TODO: mb it's dirty hack
        new_pipeline = self.strategy.get_pipeline(self)[:]
        insert_index = pipeline.index('third_party_auth.pipeline.ensure_user_information')
        new_pipeline.insert(insert_index, 'plectica_oauth_provider.pipeline.ensure_user_information')

        self.strategy.session.setdefault('auth_entry', 'login')

        return super(PlecticaOAuth2Backend, self).pipeline(
            pipeline=new_pipeline, *args, **kwargs
        )

