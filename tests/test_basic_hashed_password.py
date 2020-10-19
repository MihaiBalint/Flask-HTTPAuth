import unittest
import base64
from hashlib import md5 as basic_md5
from sanic import Sanic
from sanic_httpauth import HTTPBasicAuth
from sanic.response import text


def md5(s):
    if isinstance(s, str):
        s = s.encode("utf-8")
    return basic_md5(s)


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Sanic(__name__)
        app.config["SECRET_KEY"] = "my secret"

        basic_custom_auth = HTTPBasicAuth()

        @basic_custom_auth.get_password
        def get_basic_custom_auth_get_password(username):
            if username == "john":
                return md5("hello").hexdigest()
            elif username == "susan":
                return md5("bye").hexdigest()
            else:
                return None

        @basic_custom_auth.hash_password
        def basic_custom_auth_hash_password(password):
            return md5(password).hexdigest()

        @app.route("/")
        def index(request):
            return text("index")

        @app.route("/basic-custom")
        @basic_custom_auth.login_required
        def basic_custom_auth_route(request):
            return text(
                f"basic_custom_auth:{basic_custom_auth.username(request)}")

        self.app = app
        self.basic_custom_auth = basic_custom_auth
        self.client = app.test_client

    def test_basic_auth_login_valid_with_hash1(self):
        creds = base64.b64encode(b"john:hello").decode("utf-8")
        req, response = self.client.get(
            "/basic-custom", headers={"Authorization": "Basic " + creds}
        )
        self.assertEqual(response.content.decode("utf-8"),
                         "basic_custom_auth:john")

    def test_basic_custom_auth_login_valid(self):
        creds = base64.b64encode(b"john:hello").decode("utf-8")
        req, response = self.client.get(
            "/basic-custom", headers={"Authorization": "Basic " + creds}
        )
        self.assertEqual(response.content, b"basic_custom_auth:john")

    def test_basic_custom_auth_login_invalid(self):
        creds = base64.b64encode(b"john:bye").decode("utf-8")
        req, response = self.client.get(
            "/basic-custom", headers={"Authorization": "Basic " + creds}
        )
        self.assertEqual(response.status_code, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
