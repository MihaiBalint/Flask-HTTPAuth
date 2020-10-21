import base64
import unittest
from sanic import Sanic
from sanic_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth
from sanic.response import text


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Sanic(__name__)
        app.config["SECRET_KEY"] = "my secret"

        basic_auth = HTTPBasicAuth()
        token_auth = HTTPTokenAuth("MyToken")
        multi_auth = MultiAuth(basic_auth, token_auth)

        @basic_auth.verify_password
        def verify_password(username, password):
            return username == "john" and password == "hello"

        @token_auth.verify_token
        def verify_token(token):
            return token == "this-is-the-token!"

        @token_auth.error_handler
        def error_handler(request):
            return text(
                "error", status=401,
                headers={"WWW-Authenticate": 'MyToken realm="Foo"'}
            )

        @app.route("/")
        def index(request):
            return text("index")

        @app.route("/protected")
        @multi_auth.login_required
        def auth_route(request):
            return text("access granted")

        self.app = app
        self.client = app.test_client

    def test_multi_auth_prompt(self):
        req, response = self.client.get("/protected")
        self.assertEqual(response.status_code, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertEqual(
            response.headers["WWW-Authenticate"],
            'Basic realm="Authentication Required"',
        )

    def test_multi_auth_login_valid_basic(self):
        creds = base64.b64encode(b"john:hello").decode("utf-8")
        req, response = self.client.get(
            "/protected", headers={"Authorization": "Basic " + creds}
        )
        self.assertEqual(response.content.decode("utf-8"), "access granted")

    def test_multi_auth_login_invalid_basic(self):
        creds = base64.b64encode(b"john:bye").decode("utf-8")
        req, response = self.client.get(
            "/protected", headers={"Authorization": "Basic " + creds}
        )
        self.assertEqual(response.status_code, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertEqual(
            response.headers["WWW-Authenticate"],
            'Basic realm="Authentication Required"',
        )

    def test_multi_auth_login_valid_token(self):
        req, response = self.client.get(
            "/protected",
            headers={"Authorization": "MyToken this-is-the-token!"}
        )
        self.assertEqual(response.content.decode("utf-8"), "access granted")

    def test_multi_auth_login_invalid_token(self):
        req, response = self.client.get(
            "/protected",
            headers={"Authorization": "MyToken this-is-not-the-token!"}
        )
        self.assertEqual(response.status_code, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertEqual(response.headers["WWW-Authenticate"],
                         'MyToken realm="Foo"')

    def test_multi_auth_login_invalid_scheme(self):
        req, response = self.client.get(
            "/protected", headers={"Authorization": "Foo this-is-the-token!"}
        )
        self.assertEqual(response.status_code, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertEqual(
            response.headers["WWW-Authenticate"],
            'Basic realm="Authentication Required"',
        )

    def test_multi_malformed_header(self):
        req, response = self.client.get(
            "/protected", headers={"Authorization": "token-without-scheme"}
        )
        self.assertEqual(response.status_code, 401)
