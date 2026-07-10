from rag.stores import ioc_db, cti_store, org_store

def update_rag_from_correction(correction: dict):
    """Index analyst correction into relevant RAG store."""
    if correction["type"] == "ioc_correction":
        # Update Store 3 — IOC database
        ioc_db.execute(
            "UPDATE iocs SET exclusivity=?, analyst_verified=1 WHERE ip=?",
            (correction["new_exclusivity"], correction["ip"])
        )
        ioc_db.commit()
    elif correction["type"] == "cti_context":
        # Add new context to Store 2
        cti_store.add_texts(
            [correction["new_context"]],
            metadatas=[{"source": "analyst_correction",
                        "alert_id": correction["alert_id"]}]
        )
    elif correction["type"] == "fp_pattern":
        # Add FP pattern to Store 4
        org_store.add_texts(
            [f"False positive pattern: {correction['description']}"],
            metadatas=[{"type": "fp_pattern",
                        "category": correction["fp_category"]}]
        )
