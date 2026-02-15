def transform(param):
    import re
    match = re.search(r'SHA256=([A-Fa-f0-9]{64})', param)
    return match.group(1) if match else ''
