import streamlit as st
from database.db_manager import create_user, validate_user

def login_ui():

    st.sidebar.subheader("🔐 Login")

    login_type = st.sidebar.radio(
        "Select",
        ["Login", "Register"]
    )

    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input(
        "Password",
        type="password"
    )

    if login_type == "Register":

        if st.sidebar.button("Create Account"):

            success = create_user(username, password)

            if success:
                st.sidebar.success("Account created")

            else:
                st.sidebar.error("User already exists")

    else:

        if st.sidebar.button("Login"):

            user = validate_user(username, password)

            if user:
                st.session_state.logged_in = True
                st.session_state.username = username
                st.rerun()

            else:
                st.sidebar.error("Invalid credentials")