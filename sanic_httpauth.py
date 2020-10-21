"""
sanic_httpauth
==================

This module provides Basic and Digest HTTP authentication for Sanic routes.

:copyright: (C) 2020 by Svitlana Kost.
:copyright: (C) 2019 by Mihai Balint.
:copyright: (C) 2014 by Miguel Grinberg.
:license:   MIT, see LICENSE for more details.
"""
import logging

from functools import wraps
from hashlib import md5
from random import Random, SystemRandom
from sanic.response import text

from sanic_httpauth_compat import safe_str_cmp, Authorization
from sanic_httpauth_compat import parse_authorization_header, get_request

__version__ = "0.2.0"
log = logging.getLogger(__name__)


class HTTPAuth(object):
    def __init__(self, scheme=None, realm=None):
        self.scheme = scheme
        self.realm = realm or "Authentication Required"
        self.get_password_callback = None
        self.auth_error_callback = None

        def default_get_password(username):
            return None

        def default_auth_error(request):
            return text("Unauthorized Access", status=401)

        self.get_password(default_get_password)
        self.error_handler(default_auth_error)

    def get_password(self, f):
        self.get_password_callback = f
        return f

    def error_handler(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            request = get_request(*args, **kwargs)
            res = f(*args, **kwargs)

            if res.status == 200:
                # if user didn't set status code, use 401
                res.status = 401
            if "WWW-Authenticate" not in res.headers.keys():
                res.headers["WWW-Authenticate"] = self.authenticate_header(
                    request)
            return res

        self.auth_error_callback = decorated
        return decorated

    def authenticate_header(self, request):
        return '{0} realm="{1}"'.format(self.scheme, self.realm)

    def get_auth(self, request):
        auth = parse_authorization_header(request.headers.get("Authorization"))
        try:
            if auth is None and "Authorization" in request.headers:
                auth_headers = request.headers["Authorization"]
                auth_type, value = auth_headers.split(None, 1)
                auth = Authorization(auth_type, {"token": value})
        except ValueError:
            # The Authorization header is either empty or has no token
            pass

        # if the auth type does not match, we act as if there is no auth
        # this is better than failing directly, as it allows the callback
        # to handle special cases, like supporting multiple auth types
        if auth is not None and auth.type.lower() != self.scheme.lower():
            auth = None

        return auth

    def get_auth_password(self, auth):
        password = None

        if auth and auth.username:
            password = self.get_password_callback(auth.username)

        return password

    def login_required(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # print(*args, **kwargs)
            request = get_request(*args, **kwargs)

            auth = self.get_auth(request)
            request.ctx.authorization = auth

            # Sanic-CORS normally handles OPTIONS requests on its own,
            # but in the case it is configured to forward those to the
            # application, we need to ignore authentication headers and let
            # the request through to avoid unwanted interactions with CORS.
            if request.method != "OPTIONS":  # pragma: no cover
                password = self.get_auth_password(auth)

                if not self.authenticate(request, auth, password):
                    return self.auth_error_callback(request)

            return f(*args, **kwargs)

        return decorated

    def username(self, request):
        if not request.ctx.authorization:
            return ""
        return request.ctx.authorization.username


class HTTPBasicAuth(HTTPAuth):
    def __init__(self, scheme=None, realm=None):
        super(HTTPBasicAuth, self).__init__(scheme or "Basic", realm)

        self.hash_password_callback = None
        self.verify_password_callback = None

    def hash_password(self, f):
        self.hash_password_callback = f
        return f

    def verify_password(self, f):
        self.verify_password_callback = f
        return f

    def authenticate(self, request, auth, stored_password):
        if auth:
            username = auth.username
            client_password = auth.password
        else:
            username = ""
            client_password = ""
        if self.verify_password_callback:
            return self.verify_password_callback(username, client_password)
        if not auth:
            return False
        if self.hash_password_callback:
            try:
                client_password = self.hash_password_callback(client_password)
            except TypeError:
                client_password = self.hash_password_callback(
                    username, client_password)
        return (
            (client_password is not None and
             stored_password is not None and
             safe_str_cmp(client_password, stored_password))
        )


class HTTPDigestAuth(HTTPAuth):
    def __init__(self, scheme=None, realm=None, use_ha1_pw=False):
        super(HTTPDigestAuth, self).__init__(scheme or "Digest", realm)
        self.use_ha1_pw = use_ha1_pw
        self.random = SystemRandom()
        try:
            self.random.random()
        except NotImplementedError:  # pragma: no cover
            self.random = Random()

        self.generate_nonce_callback = None
        self.verify_nonce_callback = None
        self.generate_opaque_callback = None
        self.verify_opaque_callback = None

        def _generate_random():
            return md5(str(self.random.random()).encode("utf-8")).hexdigest()

        def default_generate_nonce(request):
            request.ctx.session["auth_nonce"] = _generate_random()
            return request.ctx.session["auth_nonce"]

        def default_verify_nonce(request, nonce):
            session_nonce = request.ctx.session.get("auth_nonce")
            if nonce is None or session_nonce is None:
                return False
            return safe_str_cmp(nonce, session_nonce)

        def default_generate_opaque(request):
            request.ctx.session["auth_opaque"] = _generate_random()
            return request.ctx.session["auth_opaque"]

        def default_verify_opaque(request, opaque):
            session_opaque = request.ctx.session.get("auth_opaque")
            if opaque is None or session_opaque is None:
                return False
            return safe_str_cmp(opaque, session_opaque)

        self.generate_nonce(default_generate_nonce)
        self.generate_opaque(default_generate_opaque)
        self.verify_nonce(default_verify_nonce)
        self.verify_opaque(default_verify_opaque)

    def generate_nonce(self, f):
        self.generate_nonce_callback = f
        return f

    def verify_nonce(self, f):
        self.verify_nonce_callback = f
        return f

    def generate_opaque(self, f):
        self.generate_opaque_callback = f
        return f

    def verify_opaque(self, f):
        self.verify_opaque_callback = f
        return f

    def get_nonce(self, request):
        return self.generate_nonce_callback(request)

    def get_opaque(self, request):
        return self.generate_opaque_callback(request)

    def generate_ha1(self, username, password):
        a1 = username + ":" + self.realm + ":" + password
        a1 = a1.encode("utf-8")
        return md5(a1).hexdigest()

    def authenticate_header(self, request):
        nonce = self.get_nonce(request)
        opaque = self.get_opaque(request)
        return '{0} realm="{1}",nonce="{2}",opaque="{3}"'.format(
            self.scheme, self.realm, nonce, opaque
        )

    def authenticate(self, request, auth, stored_password_or_ha1):
        if (
            not auth or
            not auth.username or
            not auth.realm or
            not auth.uri or
            not auth.nonce or
            not auth.response or
            not stored_password_or_ha1
        ):
            return False
        if not (self.verify_nonce_callback(request, auth.nonce)) or not (
            self.verify_opaque_callback(request, auth.opaque)
        ):
            return False
        if self.use_ha1_pw:
            ha1 = stored_password_or_ha1
        else:
            a1 = ":".join([auth.username, auth.realm, stored_password_or_ha1])
            ha1 = md5(a1.encode("utf-8")).hexdigest()
        a2 = ":".join([request.method, auth.uri])
        ha2 = md5(a2.encode("utf-8")).hexdigest()
        a3 = ":".join([ha1, auth.nonce, ha2])
        response = md5(a3.encode("utf-8")).hexdigest()
        return safe_str_cmp(response, auth.response)


class HTTPTokenAuth(HTTPAuth):
    def __init__(self, scheme="Bearer", realm=None):
        super(HTTPTokenAuth, self).__init__(scheme, realm)

        self.verify_token_callback = None

    def verify_token(self, f):
        self.verify_token_callback = f
        return f

    def authenticate(self, request, auth, stored_password):
        if auth:
            token = auth["token"]
        else:
            token = ""
        if self.verify_token_callback:
            return self.verify_token_callback(token)
        return False

    def token(self, request):
        if not request.ctx.authorization:
            return ""
        return request.ctx.authorization.get("token")


class MultiAuth(object):
    def __init__(self, main_auth, *args):
        self.main_auth = main_auth
        self.additional_auth = args

    def login_required(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            request = get_request(*args, **kwargs)
            selected_auth = None
            if "Authorization" in request.headers:
                try:
                    auth_headers = request.headers["Authorization"]
                    scheme, creds = auth_headers.split(None, 1)
                except ValueError:
                    # malformed Authorization header
                    pass
                else:
                    for auth in self.additional_auth:
                        if auth.scheme == scheme:
                            selected_auth = auth
                            break
            if selected_auth is None:
                selected_auth = self.main_auth

            return selected_auth.login_required(f)(*args, **kwargs)

        return decorated
