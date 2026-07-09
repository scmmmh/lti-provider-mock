# SPDX-FileCopyrightText: 2026-present Mark Hall <mark.hall@work.room3b.eu>
#
# SPDX-License-Identifier: MIT
"""Implementation of the mock LTI provider."""

import re
from base64 import b64decode
from datetime import datetime, timezone
from secrets import token_hex
from typing import Annotated

from fastapi import Cookie, Depends, FastAPI, Form, Header
from fastapi.exceptions import HTTPException
from fastapi.requests import Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from itsdangerous import Serializer
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT

from lti_provider_mock.settings import settings

app = FastAPI()
cookie_serializer = Serializer(secret_key="abcdefg")
jwt_key = JWK.generate(kty="RSA", size=2048, kid="lti-provider-mock-default")


def is_authenticated(authorization: Annotated[str | None, Header()] = None) -> str | None:
    """Check if the user is authenticated using one of the configured BASIC authentication users."""
    if len(settings.auth_users) > 0:
        if authorization is not None:
            match = re.match(r"Basic\s+(.+)", authorization)
            if match:
                user_pass = b64decode(match.group(1)).decode("utf-8").strip()
                match = re.match(r"([^:]*):(.*)", user_pass)
                if match:
                    username = match.group(1)
                    password = match.group(2)
                    for auth_user in settings.auth_users:
                        if auth_user.username == username and auth_user.password == password:
                            return username
        raise HTTPException(401, headers={"WWW-Authenticate": "Basic realm='LTI Provider Mock'"})
    return None


@app.get(f"{settings.route_prefix}/", response_class=HTMLResponse)
def landing(
    request: Request,
    auth_user: Annotated[str, Depends(is_authenticated)],  # noqa: ARG001
    lti_provider_mock_user: Annotated[str | None, Cookie()] = None,
):
    """Show the landing page."""
    if lti_provider_mock_user is None:
        action = f"""<a href="{request.url_for("login_form")}">Sign in</a>"""
    else:
        action = (
            f"""<a href="{request.url_for("courses_form")}">Select course</a> """
            f"""<a href="{request.url_for("logout")}">Log out</a>"""
        )
    return f"""<!DOCTYPE html>
<html lang="en">

<head>
  <title>LTI Provider Mock</title>
</head>
<body>
  <h1>LTI Provider Mock</h1>
  {action}
</body>

</html>
"""


@app.get(f"{settings.route_prefix}/login", response_class=HTMLResponse)
def login_form(request: Request, auth_user: Annotated[str, Depends(is_authenticated)]):
    """Show the login form for selecting the user to log into the LTI tool with."""
    users = "".join(
        [
            f"""<option value="{user.id}">{user.given_name} {user.family_name}</option>"""
            for user in settings.users
            if user.restricted is None or user.restricted == auth_user
        ]
    )
    return f"""<!DOCTYPE html>
<html lang="en">

<head>
  <title>Sign in</title>
</head>
<body>
  <h1>Please select the user to sign in with</h1>
  <form action="{request.url_for("login")}" method="post">
    <label>
      <span>User</span>
      <select name="userid">
        {users}
      </select>
    </label>
    <button type="submit">Sign in</button>
  </form>
</body>
</html>
"""


@app.post(f"{settings.route_prefix}/login", response_class=Response)
def login(
    request: Request,
    auth_user: Annotated[str, Depends(is_authenticated)],
    userid: Annotated[str, Form()],
    lti_provider_mock_redirect: Annotated[str | None, Cookie()] = None,
):
    """Handle the login form selection and either redirect to the modules list or individual module page."""
    for user in settings.users:
        if user.id == userid and (user.restricted is None or user.restricted == auth_user):
            if lti_provider_mock_redirect is None:
                response = RedirectResponse(request.url_for("courses_form"), status_code=303)
                response.delete_cookie("lti_provider_mock_redirect")
            else:
                response = RedirectResponse(cookie_serializer.loads(lti_provider_mock_redirect), status_code=303)
            response.set_cookie("lti_provider_mock_user", cookie_serializer.dumps(user.model_dump()))
            return response
    return login_form(request, auth_user)


@app.get(f"{settings.route_prefix}/logout", response_class=Response)
def logout(request: Request, response: Response):
    """Log the user out and redirect to the landing page."""
    response = RedirectResponse(request.url_for("landing"))
    response.delete_cookie("lti_provider_mock_user")
    return response


@app.get(f"{settings.route_prefix}/auth-reset", response_class=RedirectResponse)
def auth_reset(authorization: Annotated[str | None, Header()] = None):
    """Reset the HTTP basic authentication."""
    if authorization is None or authorization == "Basic Og==":
        return "/"
    else:
        raise HTTPException(401, headers={"WWW-Authenticate": "Basic realm='LTI Provider Mock'"})


@app.get("/courses", response_class=HTMLResponse)
def courses_form(request: Request, auth_user: Annotated[str, Depends(is_authenticated)]):  # noqa: ARG001
    """Show the course selection form."""
    courses = "".join(
        [
            f"""<li><a href="{request.url_for("lti_start_login", cid=course.id)}">{course.name}</a></li>"""
            for course in settings.courses
        ]
    )
    return f"""<!DOCTYPE html>
<html lang="en">

<head>
  <title>Course selection</title>
</head>

<body>
  <h1>Please select the course to launch the LTI login from</h1>
  <ul>
    {courses}
  </ul>
</body>

</html>
"""


@app.get(settings.route_prefix + "/courses/{cid}", response_class=Response)
def lti_start_login(
    cid: str,
    request: Request,
    auth_user: Annotated[str, Depends(is_authenticated)],  # noqa: ARG001
    lti_provider_mock_user: Annotated[str | None, Cookie()] = None,
):
    """Start the LTI login process for the given course identifier."""
    if len([course for course in settings.courses if course.id == cid]) == 0:
        raise HTTPException(404)
    if lti_provider_mock_user is None:
        response = RedirectResponse(request.url_for("login"))
        response.set_cookie(
            "lti_provider_mock_redirect", cookie_serializer.dumps(str(request.url_for("lti_start_login", cid=cid)))
        )
        return response
    login_hint = token_hex(32)
    response = HTMLResponse(f"""<!DOCTYPE html>
<html lang="en">

<head>
  <title>Starting login process</title>
</head>
<body>
  <form id="login-form" action="{settings.lti.login_url}" method="post">
    <input type="hidden" name="iss" value="{settings.lti.iss}" />
    <input
      type="hidden"
      name="target_link_uri"
      value="{settings.lti.launch_url}"
    />
    <input type="hidden" name="lti_message_hint" value="test" />
    <input type="hidden" name="client_id" value="lti-provider-mock" />
    <input type="hidden" name="lti_deployment_id" value="1" />
    <input type="hidden" id="login_hint" name="login_hint" value="{login_hint}" />
    <button type="submit">Login to the LTI tool</button>
  </form>
  <script lang="js">
    document.querySelector("#login-form").submit();
  </script>
</body>

</html
""")
    response.set_cookie("lti_provider_mock_login_hint", cookie_serializer.dumps(login_hint))
    response.set_cookie("lti_provider_mock_course", cookie_serializer.dumps(cid))
    return response


@app.post(settings.route_prefix + "/courses/{cid}", response_class=Response)
def lti_start_login_post(
    cid: str,
    request: Request,
    auth_user: Annotated[str, Depends(is_authenticated)],
    lti_provider_mock_user: Annotated[str | None, Cookie()] = None,
):
    """Handle POST requests to the LTI login start page."""
    return lti_start_login(cid, request, auth_user, lti_provider_mock_user=lti_provider_mock_user)


@app.get(f"{settings.route_prefix}/authorize", response_class=Response)
def lti_authorize(
    state: str,
    nonce: str,
    login_hint: str,
    request: Request,
    auth_user: Annotated[str, Depends(is_authenticated)],  # noqa: ARG001
    lti_provider_mock_user: Annotated[str | None, Cookie()] = None,
    lti_provider_mock_course: Annotated[str | None, Cookie()] = None,
    lti_provider_mock_login_hint: Annotated[str | None, Cookie()] = None,
):
    """Handle the LTI login authorization endpoint."""
    if lti_provider_mock_user is None:
        return RedirectResponse(request.url_for("login_form"), status_code=303)
    if lti_provider_mock_course is None:
        raise HTTPException(422, {"error": "Unknown course for login"})
    if lti_provider_mock_login_hint is None or cookie_serializer.loads(lti_provider_mock_login_hint) != login_hint:
        raise HTTPException(422, {"error": "Invalid login hint"})
    user = cookie_serializer.loads(lti_provider_mock_user)
    course = None
    for config_course in settings.courses:
        if config_course.id == cookie_serializer.loads(lti_provider_mock_course):
            course = config_course
            break
    if course is None:
        raise HTTPException(422, {"error": "Unknown course for login"})
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {
        "nonce": nonce,
        "iat": now,
        "exp": now + 300,
        "iss": settings.lti.iss,
        "aud": "lti-provider-mock",
        "sub": user["id"],
        # Deployment / Target Link Claims
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": "1",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": "http://localhost:6543/auth/lti/launch",
        # LTI Version Claims
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        # Roles Claim
        "https://purl.imsglobal.org/spec/lti/claim/roles": [],
        # Resource Link Claim
        "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
            "title": "Access the Open Computing Lab",
            "description": "",
            "id": "1",
        },
        # Context Claim
        "https://purl.imsglobal.org/spec/lti/claim/context": {
            "id": course.id,
            "label": course.name,
            "title": course.name,
            "type": ["CourseSection"],
        },
        # User
        "name": f"{user['given_name']} {user['family_name']}",
        "family_name": user["family_name"],
        "given_name": user["given_name"],
    }
    id_token = JWT(header={"kid": jwt_key.key_id, "alg": "RS256"}, claims=payload)
    id_token.make_signed_token(jwt_key)
    token = id_token.serialize()
    response = HTMLResponse(f"""<!DOCTYPE html>
<html lang="en">

<head>
  <title>Authorize</title>
</head>
<body>
  <form id="launch-form" action="http://localhost:6543/auth/lti/launch" method="post">
    <input type="hidden" name="id_token" value="{token}"/>
    <input type="hidden" name="state" value="{state}"/>
    <button type="submit">Launch the LTI tool</button>
  </form>
  <script lang="js">
    document.querySelector("#launch-form").submit();
  </script>
</body>

</html>
""")
    response.delete_cookie("lti_provider_mock_login_hint")
    return response


@app.post(f"{settings.route_prefix}/authorize", response_class=Response)
def lti_authorize_post(
    state: str,
    nonce: str,
    login_hint: str,
    request: Request,
    auth_user: Annotated[str, Depends(is_authenticated)],
    lti_provider_mock_user: Annotated[str | None, Cookie()] = None,
    lti_provider_mock_course: Annotated[str | None, Cookie()] = None,
    lti_provider_mock_login_hint: Annotated[str | None, Cookie()] = None,
):
    """Handle POST requests to the LTI authorization endpoint."""
    return lti_authorize(
        state,
        nonce,
        login_hint,
        request,
        auth_user,
        lti_provider_mock_user=lti_provider_mock_user,
        lti_provider_mock_course=lti_provider_mock_course,
        lti_provider_mock_login_hint=lti_provider_mock_login_hint,
    )


@app.get(f"{settings.route_prefix}/jwks")
def certificates():
    """Show the configured key certificates for signing purposes."""
    return {"keys": [jwt_key.export_public(as_dict=True)]}
