def get_riding_by_postal_code(postal_code):
    """Retrieve riding code based on postal code."""
    postal_code_to_riding = {
        "A1A1A1": "Riding1",
        "B2B2B2": "Riding2",
    }
    return postal_code_to_riding.get(postal_code.upper())


def get_candidates_by_riding(election_type, riding_code):
    """Fetch candidates by election type and riding code."""
    election_data = {
        'federal': {
            "Riding1": [{"Candidate Name": "John Doe", "Candidate Party": "Party A", "Candidate Code": "001"}],
            "Riding2": [{"Candidate Name": "Jane Smith", "Candidate Party": "Party B", "Candidate Code": "002"}],
        },
        'provincial': {
            "Riding1": [{"Candidate Name": "Alice Brown", "Candidate Party": "Party C", "Candidate Code": "101"}],
            "Riding2": [{"Candidate Name": "Bob White", "Candidate Party": "Party D", "Candidate Code": "102"}],
        },
    }

    type_map = {1: 'federal', 2: 'provincial'}
    candidates = election_data.get(type_map.get(election_type, ''), {}).get(riding_code, [])

    # Format candidates for template display
    return [{"name": c.get("Candidate Name", "Unknown"),
             "party": c.get("Candidate Party", "Unknown"),
             "code": c.get("Candidate Code", "Unknown")} for c in candidates]
