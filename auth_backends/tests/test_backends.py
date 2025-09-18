""" Tests for the backends. """
import datetime
import json
from calendar import timegm
from unittest.mock import call, patch, Mock

import ddt
import jwt
import responses
import six
from Cryptodome.PublicKey import RSA
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from social_core.tests.backends.oauth import OAuth2Test


@ddt.ddt
class EdXOAuth2Tests(OAuth2Test):
    """ Tests for the EdXOAuth2 backend. """

    backend_path = 'auth_backends.backends.EdXOAuth2'
    client_key = 'a-key'
    client_secret = 'a-secret-key'
    expected_username = 'jsmith'
    url_root = 'https://example.com'
    public_url_root = 'https://public.example.com'
    logout_redirect_url = 'https://example.com/logout_redirect'

    def setUp(self):
        cache.clear()
        super().setUp()
        self.key = RSA.generate(2048).export_key('PEM')

    def set_social_auth_setting(self, setting_name, value):
        """
        Set a social auth django setting during the middle of a test.
        """
        # The inherited backend defines self.name, i.e. "EDX_OAUTH2".
        backend_name = self.name

        # NOTE: We use the strategy's method, rather than override_settings, because the TestStrategy class being used
        # does not rely on Django settings.
        self.strategy.set_settings({f'SOCIAL_AUTH_{backend_name}_{setting_name}': value})

    def access_token_body(self, request):
        """ Generates a response from the provider's access token endpoint. """
        # The backend should always request JWT access tokens, not Bearer.
        body_content = request.body
        if isinstance(body_content, bytes):
            body_content = body_content.decode('utf8')
        body = six.moves.urllib.parse.parse_qs(body_content)
        self.assertEqual(body['token_type'], ['jwt'])

        expires_in = 3600
        access_token = self.create_jwt_access_token(expires_in)
        body = json.dumps({
            'scope': 'read write profile email user_id',
            'token_type': 'JWT',
            'expires_in': expires_in,
            'access_token': access_token
        })
        return (200, {}, body)

    def pre_complete_callback(self, start_url):
        """ Override to properly set up the access token response with callback. """
        responses.add_callback(
            responses.POST,
            url=self.backend.access_token_url(),
            callback=self.access_token_body,
            content_type="application/json",
        )

    def create_jwt_access_token(self, expires_in=3600, issuer=None, key=None, alg='RS512'):
        """
        Creates a signed (JWT) access token.

        Arguments:
            expires_in (int): Number of seconds after which the token expires.
            issuer (str): Issuer of the token.
            key (bytes PEM-format): Key used to sign the token.
            alg (str): Signing algorithm.

        Returns:
            str: JWT
        """
        key = key or self.key
        now = datetime.datetime.utcnow()
        expiration_datetime = now + datetime.timedelta(seconds=expires_in)
        issue_datetime = now
        payload = {
            'iss': issuer or self.url_root,
            'administrator': False,
            'iat': timegm(issue_datetime.utctimetuple()),
            'given_name': 'Joe',
            'sub': 'e3bfe0e4e7c6693efba9c3a93ee7f31b',
            'preferred_username': self.expected_username,
            'aud': 'InkocujLikyucsEdwiWatdebrEackmevLakDuifKooshkakWow',
            'scopes': ['read', 'write', 'profile', 'email', 'user_id'],
            'email': 'jsmith@example.com',
            'exp': timegm(expiration_datetime.utctimetuple()),
            'name': 'Joe Smith',
            'family_name': 'Smith',
            'user_id': '1',
        }
        access_token = jwt.encode(payload, key, algorithm=alg)
        return access_token

    def extra_settings(self):
        """
        Create extra Django settings for use with tests.
        """
        settings = super().extra_settings()
        settings.update({
            f'SOCIAL_AUTH_{self.name}_KEY': self.client_key,
            f'SOCIAL_AUTH_{self.name}_SECRET': self.client_secret,
            f'SOCIAL_AUTH_{self.name}_URL_ROOT': self.url_root,
        })
        return settings

    def test_login(self):
        self.do_login()

    def test_partial_pipeline(self):
        self.do_partial_pipeline()

    def test_logout_url(self):
        """
        Verify the property returns the provider's logout URL.
        """
        logout_url_without_query_params = f'{self.url_root}/logout'

        self.assertEqual(
            self.backend.logout_url,
            logout_url_without_query_params,
        )

        self.set_social_auth_setting('LOGOUT_REDIRECT_URL', self.logout_redirect_url)

        expected_query_params = f'?client_id={self.client_key}&redirect_url={self.logout_redirect_url}'

        self.assertEqual(
            self.backend.logout_url,
            logout_url_without_query_params + expected_query_params,
        )

    def test_authorization_url(self):
        """
        Verify the method utilizes the public URL, if one is set.
        """
        authorize_location = '/oauth2/authorize'
        self.assertEqual(self.backend.authorization_url(), self.url_root + authorize_location)

        # Now, add the public url root to the settings.
        self.set_social_auth_setting('PUBLIC_URL_ROOT', self.public_url_root)
        self.assertEqual(self.backend.authorization_url(), self.public_url_root + authorize_location)

    def test_end_session_url(self):
        """
        Verify the method returns the provider's logout URL (sans any redirect URLs in the query parameters).
        """
        logout_location = '/logout'
        self.assertEqual(self.backend.end_session_url(), self.url_root + logout_location)

        # Now, add the public url root to the settings.
        self.set_social_auth_setting('PUBLIC_URL_ROOT', self.public_url_root)
        self.assertEqual(self.backend.end_session_url(), self.public_url_root + logout_location)

    def test_user_data(self):
        user_data = self.backend.user_data(self.create_jwt_access_token())
        self.assertDictEqual(user_data, {
            'name': 'Joe Smith',
            'preferred_username': 'jsmith',
            'email': 'jsmith@example.com',
            'given_name': 'Joe',
            'user_id': '1',
            'family_name': 'Smith',
            'administrator': False
        })

    def test_extra_data(self):
        """
        Ensure that `user_id` and `refresh_token` stay in EXTRA_DATA.
        The refresh token is required to refresh the user's access
        token in cases where the client_credentials grant type is not
        being used, and the application is running on a completely
        separate domain name.
        """
        self.assertEqual(self.backend.EXTRA_DATA, [
            ('user_id', 'user_id', True),
            ('refresh_token', 'refresh_token', True),
        ])

    @ddt.data(True, False)  # test toggle enabled/disabled for authenticated user
    def test_start_method_authenticated_user_toggle_behavior(self, toggle_enabled):
        """
        Verify start() behavior specifically for authenticated users with toggle variations.
        """
        with patch('auth_backends.backends.ENABLE_OAUTH_SESSION_CLEANUP') as mock_toggle, \
             patch('auth_backends.backends.logout') as mock_logout, \
             patch('auth_backends.backends.set_custom_attribute') as mock_set_attr, \
             patch('auth_backends.backends.logger') as mock_logger:

            mock_user = Mock()
            mock_user.is_authenticated = True
            mock_user.username = 'testuser'

            mock_request = Mock()
            mock_request.user = mock_user

            self.backend.strategy.request = mock_request

            mock_toggle.is_enabled.return_value = toggle_enabled

            with patch.object(
                self.backend.__class__.__bases__[0], 'start', return_value='parent_start_result'
            ) as mock_parent_start:
                result = self.backend.start()

                mock_toggle.is_enabled.assert_called()

                mock_parent_start.assert_called_once()

                self.assertEqual(result, 'parent_start_result')

                if toggle_enabled:
                    mock_logout.assert_called_once_with(mock_request)

                    mock_set_attr.assert_has_calls([
                        call('start.session_cleanup_toggle_enabled', True),
                        call('start.has_request', True),
                        call('start.user_authenticated_before_cleanup', True),
                        call('start.logged_out_username', 'testuser'),
                        call('start.session_cleanup_performed', True),
                    ], any_order=True)

                    mock_logger.info.assert_called_with(
                        "OAuth start: Performing session cleanup for user '%s'",
                        'testuser'
                    )
                else:
                    mock_logout.assert_not_called()

                    mock_set_attr.assert_has_calls([
                        call('start.session_cleanup_toggle_enabled', False),
                        call('start.has_request', True),
                        call('start.user_authenticated_before_cleanup', True),
                        call('start.session_cleanup_performed', False),
                    ], any_order=True)

                    mock_logger.info.assert_not_called()

    @ddt.data(True, False)  # test toggle enabled/disabled for unauthenticated user
    def test_start_method_with_unauthenticated_user(self, toggle_enabled):
        """
        Verify start() behavior with unauthenticated users with toggle variations.
        """
        with patch('auth_backends.backends.ENABLE_OAUTH_SESSION_CLEANUP') as mock_toggle, \
             patch('auth_backends.backends.logout') as mock_logout, \
             patch('auth_backends.backends.set_custom_attribute') as mock_set_attr, \
             patch('auth_backends.backends.logger') as mock_logger:

            mock_user = AnonymousUser()

            mock_request = Mock()
            mock_request.user = mock_user

            self.backend.strategy.request = mock_request

            mock_toggle.is_enabled.return_value = toggle_enabled

            with patch.object(
                self.backend.__class__.__bases__[0], 'start', return_value='parent_start_result'
            ) as mock_parent_start:
                result = self.backend.start()

                mock_toggle.is_enabled.assert_called()

                mock_parent_start.assert_called_once()

                mock_logout.assert_not_called()

                mock_set_attr.assert_has_calls([
                    call('start.session_cleanup_toggle_enabled', toggle_enabled),
                    call('start.has_request', True),
                    call('start.user_authenticated_before_cleanup', False),
                    call('start.session_cleanup_performed', False),
                ], any_order=True)

                mock_logger.info.assert_not_called()

                self.assertEqual(result, 'parent_start_result')

    @ddt.data(True, False)  # test toggle enabled/disabled
    def test_start_method_handles_missing_request(self, toggle_enabled):
        """
        Verify that start() handles missing request object with proper observability and toggle variations.
        """
        with patch('auth_backends.backends.ENABLE_OAUTH_SESSION_CLEANUP') as mock_toggle, \
             patch('auth_backends.backends.logout') as mock_logout, \
             patch('auth_backends.backends.set_custom_attribute') as mock_set_attr, \
             patch('auth_backends.backends.logger') as mock_logger:

            if hasattr(self.backend.strategy, 'request'):
                self.backend.strategy.request = None

            mock_toggle.is_enabled.return_value = toggle_enabled

            with patch.object(
                self.backend.__class__.__bases__[0], 'start', return_value='parent_start_result'
            ) as mock_parent_start:
                result = self.backend.start()

                mock_toggle.is_enabled.assert_called()

                mock_logout.assert_not_called()

                mock_parent_start.assert_called_once()

                mock_set_attr.assert_has_calls([
                    call('start.session_cleanup_toggle_enabled', toggle_enabled),
                    call('start.has_request', False),
                    call('start.user_authenticated_before_cleanup', False),
                    call('start.session_cleanup_performed', False),
                ], any_order=True)

                mock_logger.info.assert_not_called()

                self.assertEqual(result, 'parent_start_result')

    @ddt.data(True, False)  # test toggle enabled/disabled
    def test_start_method_handles_request_without_user(self, toggle_enabled):
        """
        Verify that start() handles request without user attribute with proper observability and toggle variations.
        """
        with patch('auth_backends.backends.ENABLE_OAUTH_SESSION_CLEANUP') as mock_toggle, \
             patch('auth_backends.backends.logout') as mock_logout, \
             patch('auth_backends.backends.set_custom_attribute') as mock_set_attr, \
             patch('auth_backends.backends.logger') as mock_logger:

            mock_request = Mock(spec=[])

            self.backend.strategy.request = mock_request

            mock_toggle.is_enabled.return_value = toggle_enabled

            with patch.object(
                self.backend.__class__.__bases__[0], 'start', return_value='parent_start_result'
            ) as mock_parent_start:
                result = self.backend.start()

                mock_toggle.is_enabled.assert_called()

                mock_logout.assert_not_called()

                mock_parent_start.assert_called_once()

                mock_set_attr.assert_has_calls([
                    call('start.session_cleanup_toggle_enabled', toggle_enabled),
                    call('start.has_request', True),
                    call('start.user_authenticated_before_cleanup', False),
                    call('start.session_cleanup_performed', False),
                ], any_order=True)

                mock_logger.info.assert_not_called()

                self.assertEqual(result, 'parent_start_result')
