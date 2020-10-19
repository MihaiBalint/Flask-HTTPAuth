import unittest
import base64
from sanic import Sanic
from sanic_httpauth import HTTPBasicAuth
from sanic.response import text


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Sanic(__name__)
        app.config["SECRET_KEY"] = "my secret"

        basic_verify_auth = HTTPBasicAuth()

        @basic_verify_auth.verify_password
        def basic_verify_auth_verify_password(username, password):
            if username == "john":
                return password == "hello"
            elif username == "susan":
                return password == "bye"
            elif username == "":
                return True
            return False

        @basic_verify_auth.error_handler
        def error_handler(request):
            return text("error", status=403)  # use a custom error status

        @app.route("/")
        def index(request):
            return text("index")

        @app.route("/basic-verify")
        @basic_verify_auth.login_required
        def basic_verify_auth_route(request):
            anon = basic_verify_auth.username(request) == ""
            return text(
                f"basic_verify_auth:{basic_verify_auth.username(request)} "
                f"anon:{anon}"
            )

        self.app = app
        self.basic_verify_auth = basic_verify_auth
        self.client = app.test_client

    def test_verify_auth_login_valid(self):
        creds = base64.b64encode(b"susan:bye").decode("utf-8")
        req, response = self.client.get(
            "/basic-verify", headers={"Authorization": "Basic " + creds}
        )
        self.assertEqual(response.content,
                         b"basic_verify_auth:susan anon:False")

    def test_verify_auth_login_empty(self):
        req, response = self.client.get("/basic-verify")
        self.assertEqual(response.content, b"basic_verify_auth: anon:True")

    def test_verify_auth_login_invalid(self):
        creds = base64.b64encode(b"john:bye").decode("utf-8")
        req, response = self.client.get(
            "/basic-verify", headers={"Authorization": "Basic " + creds}
        )
        self.assertEqual(response.status_code, 403)
        self.assertTrue("WWW-Authenticate" in response.headers)
