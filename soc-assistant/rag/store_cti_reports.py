from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings

embedder = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

# Store 2 - CTI reports
cti_store = Chroma(
    collection_name="cti_reports",
    embedding_function=embedder,
    persist_directory="./rag/db/cti"
)
