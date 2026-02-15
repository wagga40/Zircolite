def transform(param):
    import re
    indicators = []
    
    # XOR operator in PowerShell (-bxor)
    if re.search(r'-bxor', param, re.IGNORECASE):
        indicators.append('BXOR_OP')
    
    # XOR in byte arrays [byte[]]
    if re.search(r'\[byte\[\]\].*\^', param, re.IGNORECASE):
        indicators.append('BYTE_XOR')
    
    # Common XOR key patterns (single byte keys) - match hex first
    xor_key_match = re.search(r'-bxor\s*(0x[0-9a-fA-F]+|\d+)', param, re.IGNORECASE)
    if xor_key_match:
        indicators.append('XOR_KEY:' + xor_key_match.group(1))
    
    # XOR in loops (common obfuscation pattern)
    if re.search(r'for.*-bxor|foreach.*-bxor', param, re.IGNORECASE):
        indicators.append('XOR_LOOP')
    
    return '|'.join(indicators) if indicators else ''
