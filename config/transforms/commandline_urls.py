def transform(param):
    import re
    # Match http/https/ftp URLs
    url_pattern = r'(https?://[^\s\'"<>]+|ftp://[^\s\'"<>]+)'
    matches = re.findall(url_pattern, param, re.IGNORECASE)
    # Clean up trailing punctuation
    cleaned = []
    for url in matches:
        url = url.rstrip('.,;:)]\'"')
        if len(url) > 10:
            cleaned.append(url)
    return '|'.join(cleaned) if cleaned else ''
