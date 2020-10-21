#!/usr/bin/env python
"""Basic authentication example

This example demonstrates how to protect Sanic endpoints with basic
authentication, using passwords (hashed but with an unsecure app-global salt).

After running this example, visit http://localhost:5000 in your browser. To
gain access, you can use (username=john, password=hello) or
(username=susan, password=bye).
"""
import hashlib
from sanic import Sanic, response
from sanic_httpauth import HTTPBasicAuth

app = Sanic(__name__)
auth = HTTPBasicAuth()


def hash_password(salt, password):
    salted = password + salt
    return hashlib.sha512(salted.encode("utf8")).hexdigest()


app_salt = "APP_SECRET - don't do this in production"
users = {
    "john": hash_password(app_salt, "hello"),
    "susan": hash_password(app_salt, "bye"),
}


@auth.verify_password
def verify_password(username, password):
    if username in users:
        return users.get(username) == hash_password(app_salt, password)
    return False


@app.route("/")
@auth.login_required
def index(request):
    return response.text(f"Hello, {auth.username(request)}!")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
