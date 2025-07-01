import os
import uuid
from flask import Flask, render_template, session, request, redirect, url_for
from flask_session import Session
import msal
from dotenv import load_dotenv

# Import Azure SDK libraries
from azure.identity import DefaultAzureCredential
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

# --- Step 1: Configure Credentials and MSAL App ---

# For local development, DefaultAzureCredential uses your Azure CLI login.
# When deployed to Azure, it automatically uses the app's associated managed identity.
credential = DefaultAzureCredential()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SESSION_TYPE'] = os.getenv('SESSION_TYPE', 'filesystem')
Session(app)

# MSAL Configuration
CLIENT_ID = os.getenv('CLIENT_ID')
AUTHORITY = os.getenv('AUTHORITY')
REDIRECT_PATH = os.getenv('REDIRECT_PATH')
SCOPE = os.getenv('SCOPE').split(' ') if os.getenv('SCOPE') else ["User.Read"]

# This helper function builds the MSAL app. Note it no longer needs a client_credential.
def _build_msal_app(cache=None, authority=None):
    return msal.ConfidentialClientApplication(
        CLIENT_ID, authority=authority or AUTHORITY,
        token_cache=cache)

# This helper gets the assertion token from the Managed Identity
def _get_client_assertion():
    """
    Acquires a token from the managed identity.
    This token will be used as the client_assertion to prove the app's identity.
    The scope 'api://AzureADTokenExchange' is a fixed value for this purpose.
    """
    try:
        # The scope for workload identity federation is always this value
        token_result = credential.get_token("api://AzureADTokenExchange/.default")
        return token_result.token
    except Exception as e:
        print(f"Error acquiring token for client assertion: {e}")
        return None

# (The login, logout, index, and cache functions remain the same)
# ...

# --- Step 2: Modify the 'authorized' route to use the client assertion ---

@app.route(REDIRECT_PATH)
def authorized():
    if request.args.get('state') != session.get("state"):
        return redirect(url_for("index"))
    if "error" in request.args:
        return render_template("auth_error.html", result=request.args)

    cache = _load_cache()
    if request.args.get('code'):
        # Get the assertion from the managed identity
        client_assertion = _get_client_assertion()

        if not client_assertion:
            return render_template("auth_error.html", result={"error": "Could not acquire client assertion from managed identity."})

        # Use the assertion to acquire the token for the user
        result = _build_msal_app(cache=cache).acquire_token_by_auth_code_flow(
            request.args,
            scopes=SCOPE,
            # Instead of a client_secret, we provide the signed assertion
            client_assertion=client_assertion
        )

        if "error" in result:
            return render_template("auth_error.html", result=result)

        session["user"] = result.get("id_token_claims")
        _save_cache(cache)

    return redirect(url_for("index"))

# (The rest of the code remains exactly the same as the previous version)

def _get_token_from_cache(scope=None):
    cache = _load_cache()
    cca = _build_msal_app(cache=cache)
    accounts = cca.get_accounts()
    if accounts:
        result = cca.acquire_token_silent(scope or SCOPE, account=accounts[0])
        _save_cache(cache)
        return result
    return None

def _load_cache():
    cache = msal.SerializableTokenCache()
    if session.get("token_cache"):
        cache.deserialize(session["token_cache"])
    return cache

def _save_cache(cache):
    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()

@app.route("/")
def index():
    user = session.get("user")
    return render_template("index.html", user=user)

@app.route("/login")
def login():
    session["state"] = str(uuid.uuid4())
    auth_url = _build_msal_app().initiate_auth_code_flow(
        SCOPE,
        redirect_uri=url_for("authorized", _external=True),
        state=session["state"]
    )
    return redirect(auth_url["auth_uri"])

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        AUTHORITY + "/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + url_for("index", _external=True))

@app.route("/user_info")
def user_info():
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))
    return render_template("display_user.html", user=user)

if __name__ == "__main__":
    app.run(host='localhost', port=5002, debug=os.getenv("FLASK_DEBUG") == "1")
