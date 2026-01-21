# streamlit_app.py
# Fast Streamlit app to manage PDF research papers with login and notes

import streamlit as st
import os
import hashlib
from PyPDF2 import PdfReader

# ---------------- CONFIG ----------------
DATA_DIR = "data"
PDF_DIR = os.path.join(DATA_DIR, "pdfs")
USERS = {
    "admin": hashlib.sha256("admin123".encode()).hexdigest(),
}

os.makedirs(PDF_DIR, exist_ok=True)

# ---------------- AUTH ----------------
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def login():
    st.title("📄 Research Paper Manager")
    st.subheader("Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in USERS and USERS[username] == hash_pw(password):
            st.session_state["logged_in"] = True
            st.session_state["user"] = username
            st.success("Login successful")
        else:
            st.error("Invalid username or password")

# ---------------- PDF UTIL ----------------
def render_pdf(pdf_path):
    # Fast viewing: provide a download button and direct browser link
    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()
    st.download_button("Download PDF", pdf_bytes, file_name=os.path.basename(pdf_path))

    # Link opens PDF in browser's native viewer (fast, supports large PDFs)
    st.markdown(f"**View PDF:** [Open in Browser]({pdf_path})", unsafe_allow_html=True)

# ---------------- MAIN APP ----------------
def app():
    st.sidebar.title("📚 Menu")
    choice = st.sidebar.radio("Navigate", ["Upload PDF", "View PDFs", "Edit Notes", "Logout"])

    if choice == "Upload PDF":
        st.header("Upload Research Paper (PDF)")
        uploaded = st.file_uploader("Choose a PDF file", type="pdf")
        if uploaded:
            path = os.path.join(PDF_DIR, uploaded.name)
            with open(path, "wb") as f:
                f.write(uploaded.read())
            st.success(f"Saved {uploaded.name}")

    elif choice == "View PDFs":
        st.header("Your Research Papers")
        files = os.listdir(PDF_DIR)
        if not files:
            st.info("No PDFs uploaded yet")
        else:
            selected = st.selectbox("Select a paper", files)
            path = os.path.join(PDF_DIR, selected)
            render_pdf(path)

    elif choice == "Edit Notes":
        st.header("Edit Notes for a Paper")
        files = os.listdir(PDF_DIR)
        if not files:
            st.info("No PDFs available")
        else:
            selected = st.selectbox("Select a paper", files)
            notes_file = os.path.join(PDF_DIR, selected + ".notes.txt")

            existing = ""
            if os.path.exists(notes_file):
                with open(notes_file, "r") as f:
                    existing = f.read()

            notes = st.text_area("Your notes / edits (does NOT change original PDF)", existing, height=300)
            if st.button("Save Notes"):
                with open(notes_file, "w") as f:
                    f.write(notes)
                st.success("Notes saved")

    elif choice == "Logout":
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

# ---------------- RUN ----------------
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

if not st.session_state["logged_in"]:
    login()
else:
    app()
