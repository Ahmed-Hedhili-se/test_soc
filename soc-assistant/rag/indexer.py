import requests
import json
from .stores import attck_store

def index_attck():
    """Download and index MITRE ATT&CK enterprise techniques."""
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    data = requests.get(url).json()

    documents = []
    for obj in data["objects"]:
        if obj.get("type") == "attack-pattern":
            technique_id = obj.get("external_references", [{}])[0].get("external_id", "")
            doc = f"""
            Technique: {technique_id} — {obj.get('name')}
            Tactic: {', '.join([p.get('phase_name', '') for p in obj.get('kill_chain_phases', [])])}
            Description: {obj.get('description', '')}
            Detection: {obj.get('x_mitre_detection', '')}
            """
            documents.append({"content": doc, "metadata": {"technique_id": technique_id}})

    attck_store.add_texts(
        [d["content"] for d in documents],
        metadatas=[d["metadata"] for d in documents]
    )
    print(f"Indexed {len(documents)} ATT&CK techniques")
