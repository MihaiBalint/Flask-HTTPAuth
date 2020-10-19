import unittest
from sanic import Sanic
from sanic_cors import CORS
from sanic_httpauth import HTTPTokenAuth
from sanic.response import text


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Sanic(__name__)
        app.config["SECRET_KEY"] = "my secret"
        app.config["CORS_AUTOMATIC_OPTIONS"] = True

        CORS(app)
        token_auth = HTTPTokenAuth("MyToken")

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
        @token_auth.login_required
        def token_auth_route(request):
            return text("token_auth")

        self.app = app
        self.token_auth = token_auth
        self.client = app.test_client

    def test_token_auth_prompt(self):
        rq, response = self.client.get("/protected")
        self.assertEqual(response.status, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertEqual(response.headers["WWW-Authenticate"],
                         'MyToken realm="Foo"')

    def test_token_auth_ignore_options(self):
        rq, response = self.client.options("/protected")
        self.assertEqual(response.status, 200)
        self.assertTrue("WWW-Authenticate" not in response.headers)

    def test_token_auth_login_valid(self):
        rq, response = self.client.get(
            "/protected",
            headers={"Authorization": "MyToken this-is-the-token!"}
        )
        self.assertEqual(response.content.decode("utf-8"), "token_auth")

    def test_token_auth_login_valid_different_case(self):
        rq, response = self.client.get(
            "/protected",
            headers={"Authorization": "mytoken this-is-the-token!"}
        )
        self.assertEqual(response.content.decode("utf-8"), "token_auth")

    def test_token_auth_login_invalid_token(self):
        rq, response = self.client.get(
            "/protected",
            headers={"Authorization": "MyToken this-is-not-the-token!"}
        )
        self.assertEqual(response.status, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertEqual(response.headers["WWW-Authenticate"],
                         'MyToken realm="Foo"')

    def test_token_auth_login_invalid_scheme(self):
        rq, response = self.client.get(
            "/protected", headers={"Authorization": "Foo this-is-the-token!"}
        )
        self.assertEqual(response.status, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertEqual(response.headers["WWW-Authenticate"],
                         'MyToken realm="Foo"')

    def test_token_auth_login_invalid_header(self):
        rq, response = self.client.get(
            "/protected", headers={"Authorization": "this-is-a-bad-header"}
        )
        self.assertEqual(response.status, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertEqual(response.headers["WWW-Authenticate"],
                         'MyToken realm="Foo"')

    def test_token_auth_login_invalid_no_callback(self):
        token_auth2 = HTTPTokenAuth("Token", realm="foo")

        @self.app.route("/protected2")
        @token_auth2.login_required
        def token_auth_route2(request):
            return text("token_auth2")

        rq, response = self.client.get(
            "/protected2",
            headers={"Authorization": "Token this-is-the-token!"}
        )
        self.assertEqual(response.status, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertEqual(response.headers["WWW-Authenticate"],
                         'Token realm="foo"')
