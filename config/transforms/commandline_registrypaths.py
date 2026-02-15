def transform(param):
    import re
    # Match registry paths
    reg_pattern = r'(HK[A-Z_]+\\[^\s\'"]+|HKEY_[A-Z_]+\\[^\s\'"]+)'
    matches = re.findall(reg_pattern, param, re.IGNORECASE)
    # Deduplicate and clean
    seen = set()
    cleaned = []
    for match in matches:
        match_lower = match.lower()
        if match_lower not in seen:
            seen.add(match_lower)
            cleaned.append(match)
    return '|'.join(cleaned) if cleaned else ''
