"""Django authentication backends.

For more information visit https://docs.djangoproject.com/en/dev/topics/auth/customizing/.
"""
import jwt
from django.dispatch import Signal
from social_core.backends.oauth import BaseOAuth2
import pdb

PROFILE_CLAIMS_TO_DETAILS_KEY_MAP = {
    'preferred_username': 'username',
    'email': 'email',
    'name': 'full_name',
    'given_name': 'first_name',
    'family_name': 'last_name',
    'locale': 'language',
    'user_id': 'user_id',
}


def _to_language(locale):
    """Convert locale name to language code if necessary.

    OpenID Connect locale needs to be converted to Django's language
    code. In general however, the differences between the locale names
    and language code are not very clear among different systems.

    For more information, refer to:
        http://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims
        https://docs.djangoproject.com/en/1.6/topics/i18n/#term-translation-string
    """
    return locale.replace('_', '-').lower()


class EdXOAuth2(BaseOAuth2):
    """
    IMPORTANT: The oauth2 application must have access to the ``user_id`` scope in order
    to use this backend.

    This backend automatically handles user session cleanup during OAuth authentication
    to prevent incorrect user associations and ensure proper user account creation.
    """
    # used by social-auth
    ACCESS_TOKEN_METHOD = 'POST'
    ID_KEY = 'preferred_username'

    name = 'edx-oauth2'

    DEFAULT_SCOPE = ['user_id', 'profile', 'email']
    discard_missing_values = True
    # EXTRA_DATA is used to store important data in the UserSocialAuth.extra_data field.
    # See https://python-social-auth.readthedocs.io/en/latest/backends/oauth.html?highlight=extra_data
    EXTRA_DATA = [
        # Update the stored user_id, if it's present in the response
        ('user_id', 'user_id', discard_missing_values),
        # Update the stored refresh_token, if it's present in the response
        ('refresh_token', 'refresh_token', discard_missing_values),
    ]

    # local only (not part of social-auth)
    CLAIMS_TO_DETAILS_KEY_MAP = PROFILE_CLAIMS_TO_DETAILS_KEY_MAP

    # This signal is fired after the user has successfully logged in.
    # providing_args=['user']
    auth_complete_signal = Signal()

    @property
    def logout_url(self):
        """Return the logout URL for the OAuth provider."""
        if self.setting('LOGOUT_REDIRECT_URL'):
            return f"{self.end_session_url()}?client_id={self.setting('KEY')}&" \
                   f"redirect_url={self.setting('LOGOUT_REDIRECT_URL')}"
        else:
            return self.end_session_url()

    def _clear_existing_user_session(self):
        """
        Clear any existing authenticated user session.

        This helper method safely logs out any currently authenticated user
        to prevent incorrect user associations during OAuth authentication.

        Returns:
            str or None: Username of the logged out user, if any
        """
        from django.contrib.auth import logout
        import logging

        logger = logging.getLogger(__name__)
        request = self.strategy.request if hasattr(self.strategy, 'request') else None

        if request and hasattr(request, 'user') and request.user.is_authenticated:
            existing_username = request.user.username
            logger.info(
                "OAuth authentication started with existing user session '%s'. "
                "Clearing session to ensure clean authentication flow.",
                existing_username
            )
            logout(request)
            return existing_username

        return None

    def start(self):
        """
        Initialize OAuth authentication process with session cleanup.

        Ensures clean authentication by clearing any existing user session
        before starting the OAuth flow to prevent incorrect user associations.

        Returns:
            Result of parent start() method
        """
        self._clear_existing_user_session()
        return super().start()

    def authorization_url(self):
        url_root = self.get_public_or_internal_url_root()
        return f'{url_root}/oauth2/authorize'

    def access_token_url(self):
        return f"{self.setting('URL_ROOT')}/oauth2/access_token"

    def end_session_url(self):
        url_root = self.get_public_or_internal_url_root()
        return f'{url_root}/logout'

    def auth_complete_params(self, state=None):
        params = super().auth_complete_params(state)
        # Request a JWT access token containing the user info
        params['token_type'] = 'jwt'
        return params

    def _validate_session_user_consistency(self, oauth_response):
        """
        Validate that the current session user matches the OAuth response user.

        This method ensures that any existing user session is consistent with
        the OAuth authentication response to prevent incorrect user associations.

        Args:
            oauth_response (dict): OAuth response containing user information

        Returns:
            bool: True if session is consistent or cleared, False on error
        """
        from django.contrib.auth import logout
        import logging

        logger = logging.getLogger(__name__)
        request = self.strategy.request if hasattr(self.strategy, 'request') else None

        if not (request and hasattr(request, 'user') and request.user.is_authenticated):
            return True

        try:
            oauth_username = oauth_response.get('preferred_username') or oauth_response.get('username')

            if oauth_username and request.user.username != oauth_username:
                existing_username = request.user.username
                logger.warning(
                    "User session mismatch detected during OAuth completion. "
                    "Session user: %s, OAuth user: %s. Clearing session.",
                    existing_username, oauth_username
                )
                logout(request)

            return True
        except Exception as e:
            logger.error("Error during OAuth completion validation: %s", str(e))
            return False

    def auth_complete(self, *args, **kwargs):
        """
        Complete OAuth authentication process with session validation.

        Performs session consistency validation and emits auth_complete_signal
        to ensure proper user authentication and prevent account associations.

        Args:
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments including OAuth response

        Returns:
            Authenticated user instance
        """
        # Validate session consistency with OAuth response
        oauth_response = kwargs.get('response', {})
        self._validate_session_user_consistency(oauth_response)

        user = super().auth_complete(*args, **kwargs)
        self.auth_complete_signal.send(sender=self.__class__, user=user)
        return user

    def user_data(self, access_token, *args, **kwargs):
        # The algorithm is required but unused because signature verification is skipped.
        # Note: signature verification happens earlier during the authentication process.
        decoded_access_token = jwt.decode(access_token, algorithms=["HS256"], options={"verify_signature": False})
        keys = list(self.CLAIMS_TO_DETAILS_KEY_MAP.keys()) + ['administrator', 'superuser']
        user_data = {key: decoded_access_token[key] for key in keys if key in decoded_access_token}
        return user_data

    def get_user_details(self, response):
        details = self._map_user_details(response)

        # Limits the scope of languages we can use
        locale = response.get('locale')
        if locale:
            details['language'] = _to_language(response['locale'])

        details['is_staff'] = response.get('administrator', False)
        details['is_superuser'] = response.get('superuser', False)

        return details

    def get_public_or_internal_url_root(self):
        return self.setting('PUBLIC_URL_ROOT') or self.setting('URL_ROOT')

    def _map_user_details(self, response):
        """Maps key/values from the response to key/values in the user model.

        Does not transfer any key/value that is empty or not present in the response.
        """
        dest = {}
        for source_key, dest_key in self.CLAIMS_TO_DETAILS_KEY_MAP.items():
            value = response.get(source_key)
            if value is not None:
                dest[dest_key] = value

        return dest
