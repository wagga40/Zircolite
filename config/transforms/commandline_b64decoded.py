def transform(param):
    # Minimum 20 base64 chars (5 groups of 4) to avoid false positives on normal strings
    base64_pattern = r'(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    matches = re.findall(base64_pattern, param)
    if not matches:
        return ''
    decoded_values = []
    for match in matches:
        try:
            decoded_bytes = base64.b64decode(match)
            detection = chardet.detect(decoded_bytes)
            encoding = detection.get('encoding')
            confidence = detection.get('confidence', 0) or 0
            if encoding and confidence > 0.5 and encoding.lower() in ('utf-8', 'ascii', 'utf-16le'):
                decoded_str = decoded_bytes.decode(encoding).strip()
                if decoded_str.isprintable() and len(decoded_str) > 10:
                    decoded_values.append(decoded_str)
        except:
            continue
    return '|'.join(decoded_values) if decoded_values else 'b64_detected_cannot_decode'
