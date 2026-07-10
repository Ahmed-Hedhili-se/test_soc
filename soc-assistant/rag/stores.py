from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
import sqlite3

# Security-domain embedding model
embedder = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2"
    # Later replace with SecBERT encoder for ablation study
)

# Store 1 — MITRE ATT&CK
attck_store = Chroma(
    collection_name="mitre_attck",
    embedding_function=embedder,
    persist_directory="./rag/db/attck"
)

# Store 2 — CTI reports
cti_store = Chroma(
    collection_name="cti_reports",
    embedding_function=embedder,
    persist_directory="./rag/db/cti"
)

# Store 3 — IOC database (exact lookup, not vector)
# Use a simple key-value store or SQLite for this
ioc_db = sqlite3.connect("./rag/db/iocs.db", check_same_thread=False)

# Store 4 — Organizational knowledge
org_store = Chroma(
    collection_name="org_knowledge",
    embedding_function=embedder,
    persist_directory="./rag/db/org"
)
