import streamlit as st

class Auth:
    def __init__(self):
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = False
        if 'username' not in st.session_state:
            st.session_state.username = None

    def login(self, username, password):
        # Demo credentials
        valid_credentials = {
            'demo': 'demo1234',
            'admin': 'admin123',
            'user': 'user123'
        }
        
        if username in valid_credentials and valid_credentials[username] == password:
            st.session_state.authenticated = True
            st.session_state.username = username
            return True
        return False

    def logout(self):
        st.session_state.authenticated = False
        st.session_state.username = None

    def is_authenticated(self):
        return st.session_state.authenticated

    def get_username(self):
        return st.session_state.username