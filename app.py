import os
import uuid
from flask import Flask, render_template, session, request, redirect, url_for
from flask_session import Session
import msal
import requests
from dotenv import load_dotenv

# Import Azure SDK libraries
from azure.identity import DefaultAzureCredential
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

# --- Step 1: Configure Credentials and MSAL App ---

# For local development, DefaultAzureCredential uses your Azure CLI login.
# When deployed to Azure, it automatically uses the app's associated managed identity.
# Get the Client ID of the managed identity from environment variables
managed_identity_client_id = os.getenv("MANAGED_IDENTITY_CLIENT_ID")

# When creating the credential, explicitly pass the client_id of the
# user-assigned managed identity. This removes ambiguity.
credential = DefaultAzureCredential(managed_identity_client_id=managed_identity_client_id)

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
def _build_msal_app(cache=None, authority=None, client_credential=None):
    return msal.ConfidentialClientApplication(
        CLIENT_ID, authority=authority or AUTHORITY,
        client_credential=client_credential,
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
        client_assertion = _get_client_assertion()
        if not client_assertion:
            return render_template("auth_error.html", result={"error": "Could not acquire client assertion from managed identity."})
       
        credential_dict = {
            "client_assertion": client_assertion,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        }

        # Build the MSAL app instance WITH the assertion credential
        msal_app = _build_msal_app(cache=cache, client_credential=credential_dict)

        result = msal_app.acquire_token_by_auth_code_flow(
            session.get("auth_flow", {}), # The flow from the login step
            request.args,                 # The response from Entra ID
            scopes=SCOPE
        )

        if "error" in result:
            return render_template("auth_error.html", result=result)

        session["user"] = result.get("id_token_claims")
        print(session["user"])
        _save_cache(cache)

    return redirect(url_for("index"))

# --- NEW: Route to show Azure stats ---
@app.route("/show_stats", methods=["POST"])
def show_stats():
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))

    subscription_id = request.form.get("subscription_id")
    if not subscription_id:
        return "Subscription ID is required.", 400

    # Get the customer's tenant ID from their login claims
    customer_tenant_id = user.get("tid")
    
    # --- Get an App-Only Token for the Customer's Tenant ---
    client_assertion = _get_client_assertion()
    if not client_assertion:
        return "Could not get client assertion.", 500

    credential_dict = {
        "client_assertion": client_assertion,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }

    # Build an MSAL app specifically for the customer's tenant
    customer_authority = f"https://login.microsoftonline.com/{customer_tenant_id}"
    customer_app = _build_msal_app(authority=customer_authority, client_credential=credential_dict)

    # Acquire an app-only token for the ARM API
    token_result = customer_app.acquire_token_for_client(scopes=["https://management.azure.com/.default"])
    
    if "access_token" not in token_result:
        # This usually means permissions are not granted or role is not assigned
        return render_template("stats_error.html", error_info=token_result)

    # --- Call the ARM API ---
    arm_token = token_result["access_token"]
    endpoint = f"https://management.azure.com/subscriptions/{subscription_id}/resourcegroups?api-version=2021-04-01"
    headers = {'Authorization': f'Bearer {arm_token}'}
    
    try:
        response = requests.get(endpoint, headers=headers)
        response.raise_for_status() # Raise an exception for bad status codes
        resource_groups = response.json().get("value", [])
        return render_template("stats.html", resource_groups=resource_groups, subscription_id=subscription_id)
    except requests.exceptions.HTTPError as err:
        return render_template("stats_error.html", error_info=err.response.json())


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
    # Create the auth code flow object
    login_scope = ["User.Read"]

    auth_flow = _build_msal_app().initiate_auth_code_flow(
        login_scope,
        redirect_uri=url_for("authorized", _external=True),
        state=session["state"]
    )
    session["auth_flow"] = auth_flow
    return redirect(auth_flow["auth_uri"])

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
