import streamlit as st
from openai import OpenAI
import streamlit as st
import pandas as pd
import requests
import streamlit_authenticator as stauth
from datetime import datetime
import gspread
from google.oauth2.service_account import Credentials

# ---------------- CONFIG ----------------

# Google Sheet (public view + editable)
SHEET_URL = "https://docs.google.com/spreadsheets/d/1ig9XBMyz1IXwxO8qznlQJ6Wv4u21x7hkVXN0abZbBjo/edit#gid=0"
CSV_EXPORT = SHEET_URL.replace("/edit#gid=", "/export?format=csv&gid=")

# HuggingFace API (tiny phishing model)
API_URL = "https://api-inference.huggingface.co/models/mrm8488/bert-tiny-finetuned-phishing"
headers = {}

# ---------------- FUNCTIONS ----------------

@st.cache_data
def load_users():
    df = pd.read_csv(CSV_EXPORT)
    users = {}
    for _, row in df.iterrows():
        users[row["username"]] = {
            "name": row["name"],
            "password": row["password"],
            "access": row.get("access", "free"),
            "scan_count": row.get("scan_count", 0),
            "last_scan_date": row.get("last_scan_date", "")
        }
    return df, users

def update_user_scan(username):
    df = pd.read_csv(CSV_EXPORT)
    now = datetime.now().strftime("%Y-%m-%d")
    df.loc[df["username"] == username, "scan_count"] += 1
    df.loc[df["username"] == username, "last_scan_date"] = now
    df.to_csv("users_temp.csv", index=False)

def reset_daily_scans(df):
    today = datetime.now().strftime("%Y-%m-%d")
    df["scan_count"] = df.apply(
        lambda row: 0 if row.get("last_scan_date") != today else row.get("scan_count", 0), axis=1
    )
    df.to_csv("users_temp.csv", index=False)

def add_user(username, password_hashed, name):
    df = pd.read_csv(CSV_EXPORT)
    new_row = pd.DataFrame([[username, password_hashed, name, "free", 0, ""]], 
        columns=["username", "password", "name", "access", "scan_count", "last_scan_date"])
    df = pd.concat([df, new_row], ignore_index=True)
    df.to_csv("users_temp.csv", index=False)
    st.success("✅ Account created successfully!")

# ---------------- UI ----------------

st.set_page_config(page_title="AI CyberSafe Checker", layout="centered")
st.title("🛡️ AI CyberSafe Checker")

menu = st.sidebar.radio("Menu", ["Login", "Sign Up", "Upgrade Account 💰"])

if menu == "Sign Up":
    st.subheader("🔐 Create Account")
    name = st.text_input("Full Name")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Create Account"):
        if name and username and password:
            hashed_pw = stauth.Hasher([password]).generate()[0]
            add_user(username, hashed_pw, name)
        else:
            st.warning("Please fill all fields.")

elif menu == "Upgrade Account 💰":
    st.subheader("💳 Upgrade to Premium (₦500/month)")
    st.markdown("""
    **Pay ₦500** to:
    
    - **Bank:** Fidelity Bank  
    - **Account Name:** Ebieme Bassey  
    - **Account Number:** 6681569396  

    After payment, send proof on WhatsApp:  
    👉 [https://wa.me/234XXXXXXXXXX](https://wa.me/2347031204549

    _(Replace with your phone number!)_
    """)
    st.info("After upgrade, you'll get unlimited scans.")

else:
    df, users = load_users()
    reset_daily_scans(df)

    authenticator = stauth.Authenticate(
        {k: {"name": v["name"], "password": v["password"]} for k,v in users.items()},
        "cybersafe", "auth", cookie_expiry_days=1
    )
    name, auth_status, username = authenticator.login("Login", "main")

    if auth_status == False:
        st.error("Invalid login.")
    elif auth_status == None:
        st.warning("Enter your login details.")
    elif auth_status:
        authenticator.logout("Logout", "sidebar")
        st.sidebar.success(f"Welcome, {name} 👋")

        st.markdown("### Paste the suspicious message below:")

        if users[username]["access"] == "free":
            today = datetime.now().strftime("%Y-%m-%d")
            if users[username]["last_scan_date"] != today:
                scan_count = 0
            else:
                scan_count = int(users[username]["scan_count"])
            remaining = 3 - scan_count
            st.info(f"🧪 Free scan limit: {remaining} left today")

            if remaining <= 0:
                st.warning("You’ve used your 3 free scans today. Upgrade for unlimited access.")
                st.stop()

        msg = st.text_area("✉️ Enter message here:")
        if st.button("Scan Now"):
            if msg:
                with st.spinner("Analyzing..."):
                    response = requests.post(API_URL, headers=headers, json={"inputs": msg})
                    if response.status_code == 200:
                        result = response.json()[0]
                        label = result["label"]
                        score = round(result["score"] * 100, 2)
                        if label.lower() == "phishing":
                            st.error(f"🚨 SCAM DETECTED ({score}%)")
                        else:
                            st.success(f"✅ SAFE ({score}%)")

                        if users[username]["access"] == "free":
                            update_user_scan(username)
                    else:
                        st.error("API error. Try again later.")
            else:
                st.warning("Enter a message to scan.")
# Show title and description.
st.title("💬 Chatbot")
st.write(
    "This is a simple chatbot that uses OpenAI's GPT-3.5 model to generate responses. "
    "To use this app, you need to provide an OpenAI API key, which you can get [here](https://platform.openai.com/account/api-keys). "
    "You can also learn how to build this app step by step by [following our tutorial](https://docs.streamlit.io/develop/tutorials/llms/build-conversational-apps)."
)

# Ask user for their OpenAI API key via `st.text_input`.
# Alternatively, you can store the API key in `./.streamlit/secrets.toml` and access it
# via `st.secrets`, see https://docs.streamlit.io/develop/concepts/connections/secrets-management
openai_api_key = st.text_input("OpenAI API Key", type="password")
if not openai_api_key:
    st.info("Please add your OpenAI API key to continue.", icon="🗝️")
else:

    # Create an OpenAI client.
    client = OpenAI(api_key=openai_api_key)

    # Create a session state variable to store the chat messages. This ensures that the
    # messages persist across reruns.
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Display the existing chat messages via `st.chat_message`.
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Create a chat input field to allow the user to enter a message. This will display
    # automatically at the bottom of the page.
    if prompt := st.chat_input("What is up?"):

        # Store and display the current prompt.
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        # Generate a response using the OpenAI API.
        stream = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": m["role"], "content": m["content"]}
                for m in st.session_state.messages
            ],
            stream=True,
        )

        # Stream the response to the chat using `st.write_stream`, then store it in 
        # session state.
        with st.chat_message("assistant"):
            response = st.write_stream(stream)
        st.session_state.messages.append({"role": "assistant", "content": response})
