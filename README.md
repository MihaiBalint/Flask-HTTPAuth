Sanic-HTTPAuth
==============

[![Build Status](https://travis-ci.org/miguelgrinberg/Flask-HTTPAuth.png?branch=master)](https://travis-ci.org/miguelgrinberg/Flask-HTTPAuth)

This a fork of [Flask-HTTPAuth](https://github.com/miguelgrinberg/Flask-HTTPAuth) for Sanic. It is a simple extension that provides Basic and Digest HTTP authentication for Sanic routes.

Still a work in progress, contributions are welcome.

Installation
------------
The easiest way to install this is through pip.
```
pip install Sanic-HTTPAuth
```

Basic authentication example
----------------------------

```python
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
    app.run()
```

Note: See the [Flask-HTTPAuth documentation](http://pythonhosted.org/Flask-HTTPAuth) for more complex examples that involve password hashing and custom verification callbacks.

Digest authentication example
-----------------------------

```python
from sanic import Sanic, response
from sanic_httpauth import HTTPDigestAuth
from sanic_session import Session

app = Sanic(__name__)
app.config["SECRET_KEY"] = "secret key here"
auth = HTTPDigestAuth()
Session(app)

users = {"john": "hello", "susan": "bye"}


@auth.get_password
def get_pw(username):
    if username in users:
        return users.get(username)
    return None


@app.route("/")
@auth.login_required
def index(request):
    return response.text(f"Hello, {auth.username(request)}!")


if __name__ == "__main__":
    app.run()
```

Resources
---------

- [Flask-HTTPAuth Documentation](http://flask-httpauth.readthedocs.io/en/latest/)
- [PyPI](https://pypi.org/project/Sanic-HTTPAuth)
- [Change log](https://github.com/MihaiBalint/Sanic-HTTPAuth/blob/master/CHANGES.md)
