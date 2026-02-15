def transform(param):
    import re
    # Detect various IP obfuscation techniques
    obfuscation_patterns = [
        # Hex IP (0x7f000001)
        r'0x[0-9a-fA-F]{8}',
        # Decimal IP (2130706433)
        r'^\d{9,10}$',
        # Octal IP (0177.0.0.01)
        r'0[0-7]{1,3}\.0[0-7]{1,3}\.0[0-7]{1,3}\.0[0-7]{1,3}',
        # Mixed format
        r'0x[0-9a-fA-F]+\.[0-9]+\.[0-9]+\.[0-9]+'
    ]
    for pattern in obfuscation_patterns:
        if re.match(pattern, param.strip()):
            return 'OBFUSCATED_IP:' + param
    return ''
