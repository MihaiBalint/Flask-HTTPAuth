import unittest
import base64
from sanic import Sanic
from sanic_httpauth import HTTPBasicAuth
from sanic.response import text


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Sanic(__name__)
        app.config["SECRET_KEY"] = "my secret"

        basic_auth_my_realm = HTTPBasicAuth(realm="My Realm")

        @basic_auth_my_realm.get_password
        def get_basic_password_2(username):
            if username == "john":
                return "johnhello"
            elif username == "susan":
                return "susanbye"
            else:
                return None

        @basic_auth_my_realm.hash_password
        def basic_auth_my_realm_hash_password(username, password):
            return username + password

        @basic_auth_my_realm.error_handler
        def basic_auth_my_realm_error(request):
            return text("custom error")

        @app.route("/")
        def index(request):
            return text("index")

        @app.route("/basic-with-realm")
        @basic_auth_my_realm.login_required
        def basic_auth_my_realm_route(request):
            return text(
                f"basic_auth_my_realm:{basic_auth_my_realm.username(request)}")

        self.app = app
        self.basic_auth_my_realm = basic_auth_my_realm
        self.client = app.test_client

    def test_basic_auth_prompt(self):
        req, response = self.client.get("/basic-with-realm")
        self.assertEqual(response.status_code, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertEqual(response.headers["WWW-Authenticate"],
                         'Basic realm="My Realm"')
        self.assertEqual(response.content.decode("utf-8"), "custom error")

    def test_basic_auth_login_valid(self):
        creds = base64.b64encode(b"john:hello").decode("utf-8")
        req, response = self.client.get(
            "/basic-with-realm", headers={"Authorization": "Basic " + creds}
        )
        self.assertEqual(response.content.decode("utf-8"),
                         "basic_auth_my_realm:john")

    def test_basic_auth_login_invalid(self):
        creds = base64.b64encode(b"john:bye").decode("utf-8")
        req, response = self.client.get(
            "/basic-with-realm", headers={"Authorization": "Basic " + creds}
        )
        self.assertEqual(response.status_code, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)
        self.assertEqual(response.headers["WWW-Authenticate"],
                         'Basic realm="My Realm"')
