#!/usr/bin/env python
"""Multiple authentication example

This example demonstrates how to combine two authentication methods using the
"MultiAuth" class.

The root URL for this application can be accessed via basic auth, providing
username and password, or via token auth, providing a bearer JWS token.
"""
import hashlib
from sanic import Sanic, response
from sanic_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth
from itsdangerous import TimedJSONWebSignatureSerializer as JWS


app = Sanic(__name__)
app.config["SECRET_KEY"] = "top secret!"
jws = JWS(app.config["SECRET_KEY"], expires_in=3600)

basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth("Bearer")
multi_auth = MultiAuth(basic_auth, token_auth)


def hash_password(salt, password):
    salted = password + salt
    return hashlib.sha512(salted.encode("utf8")).hexdigest()


app_salt = "APP_SECRET - don't do this in production"
users = {
    "john": hash_password(app_salt, "hello"),
    "susan": hash_password(app_salt, "bye"),
}

for user in users.keys():
    token = jws.dumps({"username": user})
    print("*** token for {}: {}\n".format(user, token))


@basic_auth.verify_password
def verify_password(username, password):
    if username in users:
        return users.get(username) == hash_password(app_salt, password)
    return False


@token_auth.verify_token
def verify_token(token):
    try:
        return "username" in jws.loads(token)
    except:  # noqa: E722
        return False


@app.route("/")
@multi_auth.login_required
def index(request):
    username = basic_auth.username(request)
    if not username:
        data = jws.loads(token_auth.token(request))
        username = data["username"]

    return response.text(f"Hello, {username}!")


if __name__ == "__main__":
    app.run()
