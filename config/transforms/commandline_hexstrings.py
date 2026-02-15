def transform(param):
    import re
    # Find hex strings (0x prefixed or continuous hex)
    hex_patterns = []
    
    # 0x prefixed hex bytes (e.g., 0x48,0x65,0x6c,0x6c,0x6f)
    ox_matches = re.findall(r'(?:0x[0-9a-fA-F]{2}[,\s]*){4,}', param)
    for match in ox_matches:
        hex_patterns.append('0x_HEX')
        # Try to decode
        try:
            hex_bytes = re.findall(r'0x([0-9a-fA-F]{2})', match)
            decoded = bytes.fromhex(''.join(hex_bytes)).decode('ascii', errors='ignore')
            if decoded.isprintable() and len(decoded) > 3:
                hex_patterns.append('DECODED:' + decoded[:50])
        except:
            pass
    
    # Continuous hex string (e.g., 48656c6c6f)
    cont_matches = re.findall(r'(?<![0-9a-fA-F])[0-9a-fA-F]{16,}(?![0-9a-fA-F])', param)
    for match in cont_matches:
        if len(match) % 2 == 0:  # Valid hex string
            hex_patterns.append('CONT_HEX')
            try:
                decoded = bytes.fromhex(match).decode('ascii', errors='ignore')
                if decoded.isprintable() and len(decoded) > 3:
                    hex_patterns.append('DECODED:' + decoded[:50])
            except:
                pass
    
    return '|'.join(hex_patterns) if hex_patterns else ''
