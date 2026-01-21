import streamlit as st
import bcrypt
from datetime import datetime
import io
import PyPDF2
from sqlalchemy import create_engine, Column, Integer, String, LargeBinary, Text, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

# ---------------- CONFIG ----------------
DATABASE_URL = "sqlite:///research.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ---------------- SESSION STATE ----------------
for key, value in {
    "logged_in": False,
    "user_id": None,
    "trash": []
}.items():
    if key not in st.session_state:
        st.session_state[key] = value

# ---------------- MODELS ----------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(LargeBinary, nullable=False)
    papers = relationship("Paper", back_populates="owner")

class Paper(Base):
    __tablename__ = "papers"
    id = Column(Integer, primary_key=True)
    filename = Column(String)
    authors = Column(String)
    year = Column(Integer)
    doi = Column(String)
    tags = Column(String)
    pdf_data = Column(LargeBinary)
    extracted_text = Column(Text)
    reading_progress = Column(Integer, default=0)
    highlights = Column(Text)
    ai_summary = Column(Text)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="papers")

# ---------------- MIGRATIONS ----------------
Base.metadata.create_all(engine)  # creates tables if not exists

# ---------------- AUTH ----------------
def hash_pw(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_pw(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)

def register_user(username: str, password: str):
    db = SessionLocal()
    try:
        db.add(User(username=username, password_hash=hash_pw(password)))
        db.commit()
        st.success("User registered successfully!")
    except:
        db.rollback()
        st.error("Username already exists")
    finally:
        db.close()

def login_user(username: str, password: str):
    db = SessionLocal()
    user = db.query(User).filter_by(username=username).first()
    db.close()
    if user and verify_pw(password, user.password_hash):
        return user.id
    return None

# ---------------- PDF HANDLING ----------------
def extract_text_from_pdf(pdf_bytes: bytes) -> str:
    reader = PyPDF2.PdfReader(io.BytesIO(pdf_bytes))
    text = ""
    for page in reader.pages:
        text += page.extract_text() or ""
    return text

def export_bibtex(paper):
    return f"""@article{{{paper.filename.split('.')[0]}_{paper.id},
  author = {{{paper.authors}}},
  year = {{{paper.year}}},
  doi = {{{paper.doi}}}
}}"""

# ---------------- UI ----------------
st.title("📚 Research Paper Manager")

# ---------------- LOGIN / REGISTER ----------------
if not st.session_state.logged_in:
    tab1, tab2 = st.tabs(["Login", "Register"])
    with tab1:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            uid = login_user(username, password)
            if uid:
                st.session_state.logged_in = True
                st.session_state.user_id = uid
                st.rerun()
            else:
                st.error("Invalid credentials")
    with tab2:
        username = st.text_input("New Username")
        password = st.text_input("New Password", type="password")
        if st.button("Register"):
            register_user(username, password)

# ---------------- MAIN APP ----------------
else:
    db = SessionLocal()
    menu = st.sidebar.radio("Menu", ["Upload", "Library", "Search", "Logout"])

    # ---------------- UPLOAD ----------------
    if menu == "Upload":
        file = st.file_uploader("Upload PDF", type="pdf")
        authors = st.text_input("Authors")
        year = st.number_input("Year", min_value=1900, max_value=2100, step=1)
        doi = st.text_input("DOI")
        tags = st.text_input("Tags (comma-separated)")
        if file and st.button("Save"):
            pdf_bytes = file.read()
            extracted = extract_text_from_pdf(pdf_bytes)
            paper = Paper(
                filename=file.name,
                authors=authors,
                year=year,
                doi=doi,
                tags=tags,
                pdf_data=pdf_bytes,
                extracted_text=extracted,
                user_id=st.session_state.user_id
            )
            db.add(paper)
            db.commit()
            st.success("Paper uploaded successfully!")

    # ---------------- LIBRARY ----------------
    elif menu == "Library":
        papers = db.query(Paper).filter_by(user_id=st.session_state.user_id).all()
        if not papers:
            st.info("No papers uploaded yet")
        else:
            # Individual Paper Display
            for p in papers:
                with st.expander(p.filename):
                    st.write(f"**Authors:** {p.authors}")
                    st.write(f"**Year:** {p.year}")
                    st.write(f"**DOI:** {p.doi}")
                    st.write(f"**Tags:** {p.tags}")
                    st.download_button("Download PDF", p.pdf_data, file_name=p.filename)
                    st.pdf(p.pdf_data, height=600)
                    st.text_area("Highlights", value=p.highlights or "", key=f"hl_{p.id}")
                    st.text_area("AI Summary (placeholder)", value=p.ai_summary or "", key=f"ai_{p.id}")
                    st.download_button("Export BibTeX", export_bibtex(p), file_name=f"{p.filename}.bib")

                    # Delete Individual Paper
                    del_key = f"del_{p.id}"
                    if st.button(f"Delete {p.filename}", key=del_key):
                        st.session_state["trash"].append(p)
                        db.delete(p)
                        db.commit()
                        st.success(f"{p.filename} deleted. You can restore it below.")
                        st.experimental_rerun()

            # Multi-Tag Bulk Delete
            all_tags = sorted({tag.strip() for paper in papers for tag in (paper.tags or "").split(",") if tag})
            if all_tags:
                st.markdown("---")
                st.subheader("Bulk Delete by Tags / Collections")
                selected_tags = st.multiselect("Select Tags to Delete Papers", all_tags)
                if selected_tags:
                    if st.button(f"Delete All Selected Tags"):
                        confirm = st.confirm(f"Are you sure you want to delete all papers with tags: {', '.join(selected_tags)}?")
                        if confirm:
                            tag_papers = []
                            for tag in selected_tags:
                                tag_papers += db.query(Paper).filter(
                                    Paper.user_id == st.session_state.user_id,
                                    Paper.tags.like(f"%{tag}%")
                                ).all()
                            st.session_state["trash"] += tag_papers
                            for tp in tag_papers:
                                db.delete(tp)
                            db.commit()
                            st.success(f"All papers with selected tags deleted. You can restore them from Trash.")
                            st.experimental_rerun()

            # Trash / Undo Section
            if st.session_state["trash"]:
                st.markdown("---")
                st.subheader("Trash / Undo Deleted Papers")

                # Restore all
                if st.button("Restore All Papers in Trash"):
                    for t in st.session_state["trash"]:
                        restored_paper = Paper(
                            filename=t.filename,
                            authors=t.authors,
                            year=t.year,
                            doi=t.doi,
                            tags=t.tags,
                            pdf_data=t.pdf_data,
                            extracted_text=t.extracted_text,
                            reading_progress=t.reading_progress,
                            highlights=t.highlights,
                            ai_summary=t.ai_summary,
                            user_id=st.session_state.user_id
                        )
                        db.add(restored_paper)
                    db.commit()
                    st.session_state["trash"] = []
                    st.success("All papers restored successfully!")
                    st.experimental_rerun()

                # Individual restore (optional)
                for t in st.session_state["trash"]:
                    with st.expander(f"{t.filename} (Deleted)"):
                        st.write(f"**Authors:** {t.authors}, **Year:** {t.year}, **Tags:** {t.tags}")
                        if st.button(f"Restore {t.filename}", key=f"restore_{t.id}"):
                            restored_paper = Paper(
                                filename=t.filename,
                                authors=t.authors,
                                year=t.year,
                                doi=t.doi,
                                tags=t.tags,
                                pdf_data=t.pdf_data,
                                extracted_text=t.extracted_text,
                                reading_progress=t.reading_progress,
                                highlights=t.highlights,
                                ai_summary=t.ai_summary,
                                user_id=st.session_state.user_id
                            )
                            db.add(restored_paper)
                            db.commit()
                            st.session_state["trash"] = [x for x in st.session_state["trash"] if x.id != t.id]
                            st.success(f"{t.filename} restored successfully!")
                            st.experimental_rerun()

    # ---------------- SEARCH ----------------
    elif menu == "Search":
        q = st.text_input("Search inside PDFs")
        if q:
            results = db.query(Paper).filter(
                Paper.user_id == st.session_state.user_id,
                Paper.extracted_text.like(f"%{q}%")
            ).all()
            st.write(f"Found {len(results)} result(s)")
            for r in results:
                st.write(f"📄 {r.filename}")

    # ---------------- LOGOUT ----------------
    elif menu == "Logout":
        st.session_state.logged_in = False
        st.session_state.user_id = None
        st.rerun()

    db.close()
