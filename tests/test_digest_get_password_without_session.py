import re
import unittest
from hashlib import md5 as basic_md5
from unittest.mock import patch

from sanic import Sanic
from sanic.response import text
from sanic_cors import CORS
from sanic_httpauth import HTTPDigestAuth
from sanic_httpauth_compat import parse_dict_header


def md5(str):
    if type(str).__name__ == "str":
        str = str.encode("utf-8")
    return basic_md5(str)


def get_ha1(user, pw, realm):
    a1 = user + ":" + realm + ":" + pw
    return md5(a1).hexdigest()


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Sanic(__name__)
        app.config["SECRET_KEY"] = "my secret"
        app.config["CORS_AUTOMATIC_OPTIONS"] = True

        CORS(app)
        digest_auth = HTTPDigestAuth(use_session=False, qop="auth")

        @digest_auth.get_password
        def get_digest_password_2(username):
            if username == "susan":
                return "hello"
            elif username == "john":
                return "bye"
            else:
                return None

        @app.route("/")
        def index(request):
            return text("index")

        @app.route("/digest")
        @digest_auth.login_required
        def digest_auth_route(request):
            return text(f"digest_auth:{digest_auth.username(request)}")

        self.app = app
        self.digest_auth = digest_auth
        self.client = app.test_client

    def test_digest_auth_prompt(self):
        req, response = self.client.get("/digest")
        self.assertEqual(response.status_code, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertTrue(
            re.match(
                r'^Digest realm="Authentication Required", '
                r'nonce="[0-9a-f]+", qop="auth", opaque="[0-9a-f]+"$',
                response.headers["WWW-Authenticate"],
            )
        )

    def test_digest_auth_ignore_options(self):
        req, response = self.client.options("/digest")
        self.assertEqual(response.status_code, 200)
        self.assertTrue("WWW-Authenticate" not in response.headers)

    @patch.object(HTTPDigestAuth, '_generate_random')
    def test_digest_auth_login_valid(self, generate_random_mock):
        generate_random_mock.side_effect = [
            "9549bf6d4fd6206e2945e8501481ddd5",
            "47c67cc7bedf6bc754f044f77f32b99e"]
        req, response = self.client.get("/digest")
        self.assertTrue(response.status_code == 401)
        header = response.headers.get("WWW-Authenticate")
        auth_type, auth_info = header.split(None, 1)
        d = parse_dict_header(auth_info)

        auth_response = "21ca18e29c5dcc5c418d95fe8bef9477"

        req, response = self.client.get(
            "/digest",
            headers={
                "Authorization": 'Digest username="john",realm="{0}",'
                'nonce="{1}",uri="/digest",response="{2}",'
                'opaque="{3}", nc="00000001",cnonce="5fd0a782"'.format(
                    d["realm"], d["nonce"], auth_response, d["opaque"]
                )
            },
        )
        print(response.content)
        self.assertEqual(response.content, b"digest_auth:john")

    def test_digest_auth_login_bad_realm(self):
        req, response = self.client.get("/digest")
        self.assertTrue(response.status_code == 401)
        self.assertTrue(response.cookies is not None)
        header = response.headers.get("WWW-Authenticate")
        auth_type, auth_info = header.split(None, 1)
        d = parse_dict_header(auth_info)

        auth_response = md5("Authentication").hexdigest()

        req, response = self.client.get(
            "/digest",
            headers={
                "Authorization": 'Digest username="john",realm="{0}",'
                'nonce="{1}",qop= "auth",uri="/digest",response="{2}",'
                'opaque="{3}"'.format(
                    d["realm"], d["nonce"], auth_response, d["opaque"]
                )
            },
        )
        self.assertEqual(response.status_code, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertTrue(
            re.match(
                r'^Digest realm="Authentication Required", '
                r'nonce="[0-9a-f]+", qop="auth", opaque="[0-9a-f]+"$',
                response.headers["WWW-Authenticate"],
            )
        )

    def test_digest_auth_login_invalid2(self):
        req, response = self.client.get("/digest")
        self.assertEqual(response.status_code, 401)
        header = response.headers.get("WWW-Authenticate")
        auth_type, auth_info = header.split(None, 1)
        d = parse_dict_header(auth_info)

        auth_response = md5("Authentication").hexdigest()

        req, response = self.client.get(
            "/digest",
            headers={
                "Authorization": 'Digest username="david",realm="{0}",'
                'nonce="{1}",uri="/digest",response="{2}",'
                'opaque="{3}"'.format(
                    d["realm"], d["nonce"], auth_response, d["opaque"]
                )
            },
        )
        self.assertEqual(response.status_code, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertTrue(
            re.match(
                r'^Digest realm="Authentication Required", '
                r'nonce="[0-9a-f]+", qop="auth", opaque="[0-9a-f]+"$',
                response.headers["WWW-Authenticate"],
            )
        )

    def test_digest_generate_ha1(self):
        ha1 = self.digest_auth.generate_ha1("pawel", "test")
        ha1_expected = get_ha1("pawel", "test", self.digest_auth.realm)
        self.assertEqual(ha1, ha1_expected)

    def test_digest_custom_nonce_checker(self):
        @self.digest_auth.generate_nonce
        def noncemaker(request):
            return "not a good nonce"

        @self.digest_auth.generate_opaque
        def opaquemaker(request):
            return "some opaque"

        verify_nonce_called = []

        @self.digest_auth.verify_nonce
        def verify_nonce(request, provided_nonce):
            verify_nonce_called.append(provided_nonce)
            return True

        verify_opaque_called = []

        @self.digest_auth.verify_opaque
        def verify_opaque(request, provided_opaque):
            verify_opaque_called.append(provided_opaque)
            return True

        req, response = self.client.get("/digest")
        self.assertEqual(response.status_code, 401)
        header = response.headers.get("WWW-Authenticate")
        auth_type, auth_info = header.split(None, 1)
        d = parse_dict_header(auth_info)

        self.assertEqual(d["nonce"], "not a good nonce")
        self.assertEqual(d["opaque"], "some opaque")

        auth_response = "648057b3e2e2cfeb838d03dba6bce576"

        req, response = self.client.get(
            "/digest",
            headers={
                "Authorization": 'Digest username="john",realm="{0}",'
                'nonce="{1}",uri="/digest",response="{2}",'
                'opaque="{3}",nc="00000001",cnonce="5fd0a782"'.format(
                    d["realm"], d["nonce"], auth_response, d["opaque"]
                )
            },
        )
        self.assertEqual(response.content, b"digest_auth:john")
        self.assertEqual(
            verify_nonce_called, ["not a good nonce"],
            "Should have verified the nonce."
        )
        self.assertEqual(
            verify_opaque_called, ["some opaque"],
            "Should have verified the opaque."
        )
