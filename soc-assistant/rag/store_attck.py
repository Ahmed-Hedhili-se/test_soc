"""
rag/store_attck.py

Store 1 - MITRE ATT&CK (Hybrid vector + BM25 conceptually).
Chroma is used for the zero-infra prototype.

IMPORTANT: the embedder and the Chroma collection are NOT created at
import time. `import rag.store_attck` must be cheap and side-effect-free
(no network calls, no model download) so that unrelated modules can import
this package without paying that cost or needing network access. The
actual store is built lazily on first call to get_attck_store(), and
cached afterwards.

Set SOC_ASSISTANT_MOCK_EMBEDDINGS=1 to force a zero-dependency fake
embedder (fixed-length zero vectors) instead of downloading a real
HuggingFace sentence-transformer model -- useful for tests/CI and for the
demo runner, where exact embedding quality doesn't matter.
"""
from __future__ import annotations

import os

_attck_store = None  # lazy singleton, populated by get_attck_store()


class SimpleFakeEmbeddings:
    """Zero-dependency stand-in embedder: fixed-length zero vectors.

    Similarity search over this embedder is meaningless (every vector is
    identical) -- it exists purely so the pipeline can run end to end
    without downloading a real model, e.g. in tests/CI or offline demos.
    """
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
        # No network / package unavailable -- degrade gracefully rather
        # than crash the whole pipeline over a knowledge-base dependency.
        return SimpleFakeEmbeddings()


def get_attck_store():
    """Return the (lazily-initialized, cached) ATT&CK Chroma collection."""
    global _attck_store
    if _attck_store is None:
        try:
            from langchain_chroma import Chroma  # modern package, no deprecation warning
        except ImportError:
            from langchain_community.vectorstores import Chroma  # fallback if not installed
        _attck_store = Chroma(
            collection_name="mitre_attck",
            embedding_function=_build_embedder(),
            persist_directory="./rag/db/attck",
        )
    return _attck_store
