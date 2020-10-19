import unittest
from hashlib import md5 as basic_md5
from sanic import Sanic
from sanic_session import Session, InMemorySessionInterface
from sanic_httpauth import HTTPDigestAuth
from sanic.response import text

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

        Session(app, interface=InMemorySessionInterface(
            cookie_name="test_session"))
        digest_auth_ha1_pw = HTTPDigestAuth(use_ha1_pw=True)

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
        header = response.headers.get("WWW-Authenticate")
        auth_type, auth_info = header.split(None, 1)
        d = parse_dict_header(auth_info)

        a1 = "john:" + d["realm"] + ":bye"
        ha1 = md5(a1).hexdigest()
        a2 = "GET:/digest_ha1_pw"
        ha2 = md5(a2).hexdigest()
        a3 = ha1 + ":" + d["nonce"] + ":" + ha2
        auth_response = md5(a3).hexdigest()

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
