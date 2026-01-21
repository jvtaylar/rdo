# streamlit_app_db.py
import streamlit as st
import os
import hashlib
import sqlite3
from datetime import datetime

# ---------------- CONFIG ----------------
DATA_DIR = "data"
PDF_DIR = os.path.join(DATA_DIR, "pdfs")
DB_PATH = os.path.join(DATA_DIR, "research_manager.db")

os.makedirs(PDF_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# ---------------- DATABASE ----------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    # Users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT
        )
    """)
    # PDFs table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS pdfs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            uploaded_by INTEGER,
            upload_date TEXT,
            FOREIGN KEY(uploaded_by) REFERENCES users(id)
        )
    """)
    # Notes table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pdf_id INTEGER,
            user_id INTEGER,
            note TEXT,
            FOREIGN KEY(pdf_id) REFERENCES pdfs(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------------- AUTH ----------------
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def register_user(username, password):
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hash_pw(password))
        )
        conn.commit()
    except sqlite3.IntegrityError:
        st.error("Username already exists")
    finally:
        conn.close()

def login_user(username, password):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cur.fetchone()
    conn.close()
    if user and user["password_hash"] == hash_pw(password):
        return user["id"]
    return None

# ---------------- PDF UTIL ----------------
def render_pdf(pdf_path):
    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()
    st.download_button("Download PDF", pdf_bytes, file_name=os.path.basename(pdf_path))
    st.pdf(pdf_bytes, height=800)

def add_pdf(filename, user_id):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO pdfs (filename, uploaded_by, upload_date) VALUES (?, ?, ?)",
        (filename, user_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()

def get_user_pdfs(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM pdfs WHERE uploaded_by=?", (user_id,))
    pdfs = cur.fetchall()
    conn.close()
    return pdfs

def get_note(pdf_id, user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT note FROM notes WHERE pdf_id=? AND user_id=?", (pdf_id, user_id))
    row = cur.fetchone()
    conn.close()
    return row["note"] if row else ""

def save_note(pdf_id, user_id, note):
    conn = get_db_connection()
    cur = conn.cursor()
    if get_note(pdf_id, user_id):
        cur.execute("UPDATE notes SET note=? WHERE pdf_id=? AND user_id=?", (note, pdf_id, user_id))
    else:
        cur.execute("INSERT INTO notes (pdf_id, user_id, note) VALUES (?, ?, ?)", (pdf_id, user_id, note))
    conn.commit()
    conn.close()

# ---------------- MAIN APP ----------------
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
    st.session_state["user_id"] = None

if not st.session_state["logged_in"]:
    st.title("📄 Research Paper Manager")
    tab = st.tabs(["Login", "Register"])
    
    with tab[0]:
        st.subheader("Login")
        username = st.text_input("Username", key="login_user")
        password = st.text_input("Password", type="password", key="login_pass")
        if st.button("Login"):
            user_id = login_user(username, password)
            if user_id:
                st.session_state["logged_in"] = True
                st.session_state["user_id"] = user_id
                st.experimental_rerun()
            else:
                st.error("Invalid username or password")
    
    with tab[1]:
        st.subheader("Register")
        new_user = st.text_input("New Username", key="reg_user")
        new_pass = st.text_input("New Password", type="password", key="reg_pass")
        if st.button("Register"):
            register_user(new_user, new_pass)
            st.success("User registered! You can now log in.")

else:
    user_id = st.session_state["user_id"]
    st.sidebar.title("📚 Menu")
    choice = st.sidebar.radio("Navigate", ["Upload PDF", "View PDFs", "Edit Notes", "Logout"])

    if choice == "Upload PDF":
        st.header("Upload Research Paper (PDF)")
        uploaded = st.file_uploader("Choose a PDF file", type="pdf")
        if uploaded:
            path = os.path.join(PDF_DIR, uploaded.name)
            with open(path, "wb") as f:
                f.write(uploaded.read())
            add_pdf(uploaded.name, user_id)
            st.success(f"Saved {uploaded.name}")

    elif choice == "View PDFs":
        st.header("Your Research Papers")
        pdfs = get_user_pdfs(user_id)
        if not pdfs:
            st.info("No PDFs uploaded yet")
        else:
            selected = st.selectbox("Select a paper", [p["filename"] for p in pdfs])
            path = os.path.join(PDF_DIR, selected)
            render_pdf(path)

    elif choice == "Edit Notes":
        st.header("Edit Notes for a Paper")
        pdfs = get_user_pdfs(user_id)
        if not pdfs:
            st.info("No PDFs available")
        else:
            selected_pdf = st.selectbox("Select a paper", [p["filename"] for p in pdfs])
            pdf_id = [p["id"] for p in pdfs if p["filename"] == selected_pdf][0]
            path = os.path.join(PDF_DIR, selected_pdf)
            render_pdf(path)

            note_text = get_note(pdf_id, user_id)
            new_note = st.text_area("Your notes (will not modify PDF)", value=note_text, height=300)
            if st.button("Save Notes"):
                save_note(pdf_id, user_id, new_note)
                st.success("Notes saved")

    elif choice == "Logout":
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.experimental_rerun()
