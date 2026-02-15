def transform(param):
    import re
    match = re.search(r'MD5=([A-Fa-f0-9]{32})', param)
    return match.group(1) if match else ''
