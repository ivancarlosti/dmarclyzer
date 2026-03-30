import os
import urllib.parse
import base64
import requests
import streamlit as st

def get_keycloak_url():
    base = os.environ.get("KEYCLOAK_BASE_URL", "").rstrip("/")
    realm = os.environ.get("KEYCLOAK_REALM", "")
    client_id = os.environ.get("KEYCLOAK_CLIENT_ID", "")
    redirect_uri = os.environ.get("KEYCLOAK_REDIRECT_URI", "")
    
    auth_url = f"{base}/realms/{realm}/protocol/openid-connect/auth"
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": "openid email profile"
    }
    return f"{auth_url}?{urllib.parse.urlencode(params)}"

def authenticate_keycloak():
    # If code is in query params, we are returning from redirect
    query_params = st.query_params
    if "code" in query_params:
        code = query_params["code"]
        
        base = os.environ.get("KEYCLOAK_BASE_URL", "").rstrip("/")
        realm = os.environ.get("KEYCLOAK_REALM", "")
        client_id = os.environ.get("KEYCLOAK_CLIENT_ID", "")
        client_secret = os.environ.get("KEYCLOAK_CLIENT_SECRET", "")
        redirect_uri = os.environ.get("KEYCLOAK_REDIRECT_URI", "")
        
        token_url = f"{base}/realms/{realm}/protocol/openid-connect/token"
        
        # Use HTTP Basic Auth for client credentials
        auth_string = f"{client_id}:{client_secret}"
        auth_bytes = auth_string.encode("utf-8")
        auth_b64 = base64.b64encode(auth_bytes).decode("utf-8")
        
        headers = {
            "Authorization": f"Basic {auth_b64}",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri
        }
        
        try:
            res = requests.post(token_url, headers=headers, data=data)
            res.raise_for_status()
            tokens = res.json()
            access_token = tokens.get("access_token")
            
            if not access_token:
                st.error("Authentication failed: No access token returned.")
                return False
                
            # Get user info to verify email
            userinfo_url = f"{base}/realms/{realm}/protocol/openid-connect/userinfo"
            u_res = requests.get(userinfo_url, headers={"Authorization": f"Bearer {access_token}"})
            u_res.raise_for_status()
            userinfo = u_res.json()
            
            allowed_email = os.environ.get("KEYCLOAK_EMAIL_ACCOUNT", "")
            user_email = userinfo.get("email", "")
            
            if allowed_email and user_email.lower() != allowed_email.lower():
                st.error(f"Access denied for email: {user_email}.")
                st.query_params.clear()
                return False
                
            st.session_state["authenticated"] = True
            
            # Clear params
            st.query_params.clear()
            st.rerun()
            
        except Exception as e:
            st.error(f"Authentication failed: {e}")
            if hasattr(e, "response") and e.response is not None:
                st.error(e.response.text)
            return False

    if not st.session_state.get("authenticated", False):
        st.markdown(f'''
            <div style="display:flex; justify-content:center; align-items:center; height:50vh;">
                <a href="{get_keycloak_url()}" target="_self" style="display:inline-block;padding:15px 30px;background-color:#4CAF50;color:white;text-decoration:none;border-radius:4px;font-weight:bold;font-size:18px;">
                    Login with Keycloak SSO
                </a>
            </div>
            ''', unsafe_allow_html=True)
        return False
        
    return True

def require_auth():
    auth_method = os.environ.get("AUTH_METHOD", "none").lower()
    
    if auth_method == "none":
        return True
        
    if st.session_state.get("authenticated", False):
        return True
        
    # User is not authenticated, render login UI
    
    # We want to clear whitespace to make it look clean like the main app
    hide_st_style = """
        <style>
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        .block-container {
            padding-top: 2rem !important;
        }
        </style>
    """
    st.markdown(hide_st_style, unsafe_allow_html=True)
    
    st.title("🛡️ Authentication Required")
    
    if auth_method == "account":
        site_key = os.environ.get("RECAPTCHA_CLIENTID")
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            with st.form("login_form"):
                st.subheader("Secure Login")
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                
                if site_key:
                    st.info("ℹ️ ReCaptcha logic has been prepared for standard verification API. A frontend component must be deployed to pass the token into Streamlit session state.")
                    
                submitted = st.form_submit_button("Sign In")
                
                if submitted:
                    if username == os.environ.get("ACCOUNT_LOGIN") and password == os.environ.get("ACCOUNT_PASSWORD"):
                        st.session_state["authenticated"] = True
                        st.rerun()
                    else:
                        st.error("Invalid credentials.")
        return False
        
    elif auth_method == "keycloak":
        return authenticate_keycloak()
        
    else:
        st.error(f"Unknown AUTH_METHOD '{auth_method}' configured.")
        return False
