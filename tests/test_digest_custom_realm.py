import unittest
import re
from sanic import Sanic
from sanic_session import Session
from sanic_httpauth import HTTPDigestAuth
from sanic.response import text


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Sanic(__name__)
        app.config["SECRET_KEY"] = "my secret"
        Session(app)

        digest_auth_my_realm = HTTPDigestAuth(realm="My Realm")

        @digest_auth_my_realm.get_password
        def get_digest_password_3(username):
            if username == "susan":
                return "hello"
            elif username == "john":
                return "bye"
            else:
                return None

        @app.route("/")
        def index(request):
            return text("index")

        @app.route("/digest-with-realm")
        @digest_auth_my_realm.login_required
        def digest_auth_my_realm_route(request):
            return text(f"digest_auth_my_realm:"
                        f"{digest_auth_my_realm.username(request)}")

        self.app = app
        self.client = app.test_client

    def test_digest_auth_prompt_with_custom_realm(self):
        req, response = self.client.get("/digest-with-realm")
        self.assertEqual(response.status_code, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertTrue(
            re.match(
                r'^Digest realm="My Realm",'
                'nonce="[0-9a-f]+",opaque="[0-9a-f]+"$',
                response.headers["WWW-Authenticate"],
            )
        )

    def test_digest_auth_login_invalid(self):
        req, response = self.client.get(
            "/digest-with-realm",
            headers={
                "Authorization": 'Digest username="susan",'
                'realm="My Realm",'
                'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",'
                'uri="/digest-with-realm",'
                'response="ca306c361a9055b968810067a37fb8cb",'
                'opaque="5ccc069c403ebaf9f0171e9517f40e41"'
            },
        )
        self.assertEqual(response.status_code, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertTrue(
            re.match(
                r'^Digest realm="My Realm",'
                r'nonce="[0-9a-f]+",opaque="[0-9a-f]+"$',
                response.headers["WWW-Authenticate"],
            )
        )
