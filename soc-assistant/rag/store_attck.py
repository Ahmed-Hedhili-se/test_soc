from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings

embedder = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

# Store 1 - MITRE ATT&CK (Hybrid vector + BM25 conceptually)
# We use Chroma for prototype zero-infra
attck_store = Chroma(
    collection_name="mitre_attck",
    embedding_function=embedder,
    persist_directory="./rag/db/attck"
)
