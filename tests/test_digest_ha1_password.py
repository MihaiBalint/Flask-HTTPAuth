import unittest
from hashlib import md5 as basic_md5
from unittest.mock import MagicMock

from sanic import Sanic
from sanic.response import text
from sanic_httpauth import HTTPDigestAuth
from sanic_httpauth_compat import parse_dict_header
from sanic_session import InMemorySessionInterface, Session


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
        self.nonce = None
        self.opaque = None

        Session(app, interface=InMemorySessionInterface(
            cookie_name="test_session"))

        digest_auth_ha1_pw = HTTPDigestAuth(use_ha1_pw=True, qop=None)
        digest_auth_ha1_pw._generate_random = MagicMock(
            side_effect=["9549bf6d4fd6206e2945e8501481ddd5",
                         "47c67cc7bedf6bc754f044f77f32b99e"])

        @digest_auth_ha1_pw.get_password
        def get_digest_password(username):
            if username == "susan":
                return get_ha1(username, "hello", digest_auth_ha1_pw.realm)
            elif username == "john":
                return get_ha1(username, "bye", digest_auth_ha1_pw.realm)
            else:
                return None

        @app.route("/")
        def index(request):
            return "index"

        @app.route("/digest_ha1_pw")
        @digest_auth_ha1_pw.login_required
        def digest_auth_ha1_pw_route(request):
            return text(
                f"digest_auth_ha1_pw:{digest_auth_ha1_pw.username(request)}")

        self.app = app
        self.client = app.test_client

    def test_digest_ha1_pw_auth_login_valid(self):
        req, response = self.client.get("/digest_ha1_pw")
        self.assertTrue(response.status_code == 401)
        header = (f'Digest realm="Authentication Required", '
                  f'nonce="9549bf6d4fd6206e2945e8501481ddd5", qop="None", '
                  f'opaque="47c67cc7bedf6bc754f044f77f32b99e"')
        response.headers["WWW-Authenticate"] = header
        auth_type, auth_info = header.split(None, 1)
        d = parse_dict_header(auth_info)

        auth_response = "7afa823fb21430c8acb89ed054a5add6"
        req, response = self.client.get(
            "/digest_ha1_pw",
            headers={
                "Authorization": 'Digest username="john",realm="{0}",'
                'nonce="{1}",uri="/digest_ha1_pw",'
                'response="{2}",'
                'opaque="{3}"'.format(
                    d["realm"], d["nonce"], auth_response, d["opaque"]
                )
            },
            cookies={"test_session": response.cookies.get("test_session")},
        )
        self.assertEqual(response.content, b"digest_auth_ha1_pw:john")
