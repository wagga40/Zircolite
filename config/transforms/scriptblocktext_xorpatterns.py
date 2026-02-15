def transform(param):
    import re
    results = []
    
    # -bxor operator with key
    bxor_matches = re.findall(r'-bxor\s*(\d+|0x[0-9a-fA-F]+)', param, re.IGNORECASE)
    for key in bxor_matches:
        results.append('XOR_KEY:' + key)
    
    # XOR in foreach/for loops
    if re.search(r'foreach.*-bxor|for\s*\(.*-bxor', param, re.IGNORECASE):
        results.append('XOR_LOOP')
    
    # Byte array XOR patterns
    if re.search(r'\[byte\[\]\].*-bxor|\[System\.Byte\[\]\].*-bxor', param, re.IGNORECASE):
        results.append('BYTE_ARRAY_XOR')
    
    # Common single-byte XOR keys (often used in malware)
    for key in ['0x35', '0x55', '0xAA', '0xFF', '35', '55', '170', '255']:
        if re.search(r'-bxor\s*' + key + r'\b', param, re.IGNORECASE):
            results.append('COMMON_XOR_KEY:' + key)
    
    return '|'.join(results) if results else ''
