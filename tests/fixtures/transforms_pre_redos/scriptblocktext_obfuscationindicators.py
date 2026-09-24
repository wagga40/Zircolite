def transform(param):
    import re
    indicators = []
    
    # Character substitution (e.g., `I`E`X)
    if re.search(r'`[A-Za-z]', param):
        indicators.append('CHAR_SUBST')
    
    # String concatenation (e.g., 'Inv'+'oke')
    if re.search(r"'[^']+'\s*\+\s*'[^']+'", param):
        indicators.append('STR_CONCAT')
    
    # -Join operator obfuscation
    if re.search(r'-[jJ][oO][iI][nN]', param):
        indicators.append('JOIN_OP')
    
    # Format string obfuscation
    if re.search(r'-[fF]\s*[\'"]', param):
        indicators.append('FORMAT_STR')
    
    # Variable substitution in strings
    if re.search(r'\$\{[^}]+\}', param):
        indicators.append('VAR_SUBST')
    
    # Encoded command indicator
    if re.search(r'-[eE][nN][cC][oO]?[dD]?[eE]?[dD]?[cC]?[oO]?[mM]?[mM]?[aA]?[nN]?[dD]?', param):
        indicators.append('ENC_CMD')
    
    # GzipStream / IO.Compression obfuscation
    if re.search(r'[Gg][Zz][Ii][Pp][Ss][Tt][Rr][Ee][Aa][Mm]', param, re.IGNORECASE):
        indicators.append('GZIPSTREAM')
    
    # FromBase64String obfuscation
    if re.search(r'[Ff][Rr][Oo][Mm][Bb][Aa][Ss][Ee]64[Ss][Tt][Rr][Ii][Nn][Gg]', param, re.IGNORECASE):
        indicators.append('FROMBASE64')
    
    # IO.Compression namespace
    if re.search(r'[Ii][Oo]\.[Cc][Oo][Mm][Pp][Rr][Ee][Ss][Ss][Ii][Oo][Nn]', param, re.IGNORECASE):
        indicators.append('IO_COMPRESSION')
    
    # DeflateStream obfuscation
    if re.search(r'[Dd][Ee][Ff][Ll][Aa][Tt][Ee][Ss][Tt][Rr][Ee][Aa][Mm]', param, re.IGNORECASE):
        indicators.append('DEFLATESTREAM')
    
    # MemoryStream obfuscation
    if re.search(r'[Mm][Ee][Mm][Oo][Rr][Yy][Ss][Tt][Rr][Ee][Aa][Mm]', param, re.IGNORECASE):
        indicators.append('MEMORYSTREAM')
    
    return '|'.join(indicators) if indicators else ''
