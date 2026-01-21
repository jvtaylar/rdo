# streamlit_app_advanced.py
# Advanced Research Paper Manager
# - PostgreSQL backend
# - Automatic migrations (schema versioning)
# - PDF full-text search
# - Metadata support (authors, year, DOI)

import streamlit as st
import hashlib
from datetime import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, LargeBinary, Text, DateTime, ForeignKey
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy.exc import OperationalError
import PyPDF2
import io

# ---------------- CONFIG ----------------
DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/research_db"
SCHEMA_VERSION = 1

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ---------------- SESSION STATE ----------------
for key, value in {
    "logged_in": False,
    "user_id": None
}.items():
    if key not in st.session_state:
        st.session_state[key] = value

# ---------------- MODELS ----------------
class SchemaVersion(Base):
    __tablename__ = "schema_version"
    id = Column(Integer, primary_key=True)
    version = Column(Integer)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password_hash = Column(String)
    papers = relationship("Paper", back_populates="owner")

class Paper(Base):
    __tablename__ = "papers"
    id = Column(Integer, primary_key=True)
    filename = Column(String)
    authors = Column(String)
    year = Column(Integer)
    doi = Column(String)
    pdf_data = Column(LargeBinary)
    extracted_text = Column(Text)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User", back_populates="papers")

# ---------------- MIGRATIONS ----------------
def run_migrations():
    Base.metadata.create_all(engine)
    db = SessionLocal()
    try:
        version_row = db.query(SchemaVersion).first()
        if not version_row:
            db.add(SchemaVersion(version=SCHEMA_VERSION))
            db.commit()
    except OperationalError:
        pass
    finally:
        db.close()

run_migrations()

# ---------------- AUTH ----------------
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def login_user(username, password):
    db = SessionLocal()
    user = db.query(User).filter_by(username=username).first()
    db.close()
    if user and user.password_hash == hash_pw(password):
        return user.id
    return None

def register_user(username, password):
    db = SessionLocal()
    try:
        db.add(User(username=username, password_hash=hash_pw(password)))
        db.commit()
        st.success("User registered")
    except:
        db.rollback()
        st.error("Username exists")
    finally:
        db.close()

# ---------------- PDF PROCESSING ----------------
def extract_text_from_pdf(pdf_bytes):
    reader = PyPDF2.PdfReader(io.BytesIO(pdf_bytes))
    text = ""
    for page in reader.pages:
        text += page.extract_text() or ""
    return text

# ---------------- UI ----------------
st.title("📚 Advanced Research Paper Manager")

if not st.session_state.logged_in:
    tab1, tab2 = st.tabs(["Login", "Register"])

    with tab1:
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.button("Login"):
            uid = login_user(u, p)
            if uid:
                st.session_state.logged_in = True
                st.session_state.user_id = uid
                st.rerun()
            else:
                st.error("Invalid credentials")

    with tab2:
        u = st.text_input("New Username")
        p = st.text_input("New Password", type="password")
        if st.button("Register"):
            register_user(u, p)

else:
    db = SessionLocal()
    menu = st.sidebar.radio("Menu", ["Upload", "Library", "Search", "Logout"])

    if menu == "Upload":
        file = st.file_uploader("Upload PDF", type="pdf")
        authors = st.text_input("Authors")
        year = st.number_input("Year", min_value=1900, max_value=2100, step=1)
        doi = st.text_input("DOI")

        if file and st.button("Save"):
            pdf_bytes = file.read()
            text = extract_text_from_pdf(pdf_bytes)
            paper = Paper(
                filename=file.name,
                authors=authors,
                year=year,
                doi=doi,
                pdf_data=pdf_bytes,
                extracted_text=text,
                user_id=st.session_state.user_id
            )
            db.add(paper)
            db.commit()
            st.success("Paper uploaded")

    elif menu == "Library":
        papers = db.query(Paper).filter_by(user_id=st.session_state.user_id).all()
        for p in papers:
            with st.expander(p.filename):
                st.write(f"**Authors:** {p.authors}")
                st.write(f"**Year:** {p.year}")
                st.write(f"**DOI:** {p.doi}")
                st.download_button("Download", p.pdf_data, file_name=p.filename)
                st.pdf(p.pdf_data, height=600)

    elif menu == "Search":
        q = st.text_input("Search inside PDFs")
        if q:
            results = db.query(Paper).filter(
                Paper.user_id == st.session_state.user_id,
                Paper.extracted_text.ilike(f"%{q}%")
            ).all()
            st.write(f"Found {len(results)} result(s)")
            for r in results:
                st.write(f"📄 {r.filename}")

    elif menu == "Logout":
        st.session_state.logged_in = False
        st.session_state.user_id = None
        st.rerun()

    db.close()
