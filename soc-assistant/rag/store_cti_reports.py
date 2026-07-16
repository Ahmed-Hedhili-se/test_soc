"""
rag/store_cti_reports.py

Store 2 - CTI reports (Mandiant, CrowdStrike, Unit42, CISA), hybrid
retrieval filtered by techniques_mentioned in the real design; Chroma
similarity search for this prototype.

Same lazy-init contract as rag/store_attck.py -- see that module's
docstring for why the store is built on first use rather than at import.
"""
from __future__ import annotations

import os

_cti_store = None  # lazy singleton, populated by get_cti_store()


class SimpleFakeEmbeddings:
    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [[0.0] * 384 for _ in texts]

    def embed_query(self, text: str) -> list[float]:
        return [0.0] * 384


def _build_embedder():
    if os.environ.get("SOC_ASSISTANT_MOCK_EMBEDDINGS") == "1":
        return SimpleFakeEmbeddings()
    try:
        from langchain_huggingface import HuggingFaceEmbeddings
        return HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
    except Exception:
        return SimpleFakeEmbeddings()


def get_cti_store():
    """Return the (lazily-initialized, cached) CTI reports Chroma collection."""
    global _cti_store
    if _cti_store is None:
        try:
            from langchain_chroma import Chroma  # modern package, no deprecation warning
        except ImportError:
            from langchain_community.vectorstores import Chroma  # fallback if not installed
        _cti_store = Chroma(
            collection_name="cti_reports",
            embedding_function=_build_embedder(),
            persist_directory="./rag/db/cti",
        )
    return _cti_store
