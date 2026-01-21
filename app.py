# streamlit_app_db_files.py
# Streamlit app: PDFs stored directly in SQLite database (BLOB)

import streamlit as st
import sqlite3
import hashlib
from datetime import datetime

# ---------------- CONFIG ----------------
DB_PATH = "data/research_manager.db"

# ---------------- SESSION STATE INIT ----------------
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
if "user_id" not in st.session_state:
    st.session_state["user_id"] = None

# ---------------- DATABASE ----------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS pdfs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            pdf_data BLOB,
            uploaded_by INTEGER,
            upload_date TEXT,
            FOREIGN KEY(uploaded_by) REFERENCES users(id)
        )
    """)

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
        st.success("User registered")
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

# ---------------- PDF OPS ----------------
def save_pdf_to_db(filename, pdf_bytes, user_id):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO pdfs (filename, pdf_data, uploaded_by, upload_date) VALUES (?, ?, ?, ?)",
        (filename, pdf_bytes, user_id, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

def get_user_pdfs(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, filename FROM pdfs WHERE uploaded_by=?", (user_id,))
    rows = cur.fetchall()
    conn.close()
    return rows

def get_pdf_data(pdf_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT pdf_data, filename FROM pdfs WHERE id=?", (pdf_id,))
    row = cur.fetchone()
    conn.close()
    return row

# ---------------- NOTES ----------------
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
        cur.execute(
            "UPDATE notes SET note=? WHERE pdf_id=? AND user_id=?",
            (note, pdf_id, user_id)
        )
    else:
        cur.execute(
            "INSERT INTO notes (pdf_id, user_id, note) VALUES (?, ?, ?)",
            (pdf_id, user_id, note)
        )
    conn.commit()
    conn.close()

# ---------------- UI ----------------
if not st.session_state["logged_in"]:
    st.title("📄 Research Paper Manager (DB Stored PDFs)")
    tab1, tab2 = st.tabs(["Login", "Register"])

    with tab1:
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.button("Login"):
            uid = login_user(u, p)
            if uid:
                st.session_state["logged_in"] = True
                st.session_state["user_id"] = uid
                st.rerun()
            else:
                st.error("Invalid credentials")

    with tab2:
        u = st.text_input("New Username")
        p = st.text_input("New Password", type="password")
        if st.button("Register"):
            register_user(u, p)

else:
    user_id = st.session_state["user_id"]
    st.sidebar.title("📚 Menu")
    choice = st.sidebar.radio("Navigate", ["Upload PDF", "View PDFs", "Edit Notes", "Logout"])

    if choice == "Upload PDF":
        uploaded = st.file_uploader("Upload PDF", type="pdf")
        if uploaded:
            save_pdf_to_db(uploaded.name, uploaded.read(), user_id)
            st.success("PDF stored in database")

    elif choice == "View PDFs":
        pdfs = get_user_pdfs(user_id)
        if not pdfs:
            st.info("No PDFs uploaded")
        else:
            selected = st.selectbox("Select PDF", pdfs, format_func=lambda x: x["filename"])
            row = get_pdf_data(selected["id"])
            st.download_button("Download PDF", row["pdf_data"], file_name=row["filename"])
            st.pdf(row["pdf_data"], height=800)

    elif choice == "Edit Notes":
        pdfs = get_user_pdfs(user_id)
        if not pdfs:
            st.info("No PDFs available")
        else:
            selected = st.selectbox("Select PDF", pdfs, format_func=lambda x: x["filename"])
            note = get_note(selected["id"], user_id)
            new_note = st.text_area("Notes", note, height=300)
            if st.button("Save Notes"):
                save_note(selected["id"], user_id, new_note)
                st.success("Notes saved")

    elif choice == "Logout":
        st.session_state["logged_in"] = False
        st.session_state["user_id"] = None
        st.rerun()
