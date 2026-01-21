# streamlit_app.py
# Simple Streamlit app to upload, view, and lightly edit (notes/metadata) PDF research papers
# Username & password authentication (basic, demo-level)

import streamlit as st
import os
import hashlib
from PyPDF2 import PdfReader

# ---------------- CONFIG ----------------
DATA_DIR = "data"
PDF_DIR = os.path.join(DATA_DIR, "pdfs")
USERS = {
    # demo users: username -> sha256(password)
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
def extract_text(pdf_path):
    reader = PdfReader(pdf_path)
    text = ""
    for page in reader.pages:
        text += page.extract_text() or ""
    return text

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
            with open(path, "rb") as f:
                st.download_button("Download PDF", f, file_name=selected)
            st.subheader("Preview (Text Extract)")
            st.text_area("", extract_text(path)[:5000], height=400)

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
        st.session_state.clear()
        st.experimental_rerun()

# ---------------- RUN ----------------
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

if not st.session_state["logged_in"]:
    login()
else:
    app()

# ---------------- NOTES ----------------
# This app:
# - Uploads and stores PDFs locally
# - Allows viewing & text extraction
# - Allows editing notes (not modifying PDF content itself)
# For full PDF editing (highlight, annotate, rewrite), integrate:
# - streamlit-pdf-viewer + PyMuPDF (fitz)
# - or external annotation libraries
