import os
import streamlit as st

from dashboard.dashboard_page import page_dashboard
from dashboard.history_page import page_history
from dashboard.landing_page import page_landing

# ─────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="Nebuloupe · Cloud Misconfiguration Security Scanner",
    page_icon="🔭",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─────────────────────────────────────────────
# GLOBAL CSS
# ─────────────────────────────────────────────
def load_global_css():
    css_path = os.path.join(os.path.dirname(__file__), "dashboard", "styles.css")
    with open(css_path, "r", encoding="utf-8") as css_file:
        st.markdown(f"<style>{css_file.read()}</style>", unsafe_allow_html=True)


load_global_css()
# ─────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────
if "page" not in st.session_state:
    st.session_state.page = "landing"
if "selected_clouds" not in st.session_state:
    st.session_state.selected_clouds = []
if "results" not in st.session_state:
    st.session_state.results = None
if "scanning" not in st.session_state:
    st.session_state.scanning = False


# ─────────────────────────────────────────────
# ROUTER
# ─────────────────────────────────────────────
if st.session_state.page == "landing":
    page_landing()
elif st.session_state.page == "dashboard":
    page_dashboard()
elif st.session_state.page == "history":
    page_history()