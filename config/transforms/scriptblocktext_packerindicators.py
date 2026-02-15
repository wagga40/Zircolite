def transform(param):
    import re
    findings = []
    param_lower = param.lower()

    # GZip/Deflate compression
    if re.search(r'gzipstream|io\.compression\.compressionmode', param_lower):
        findings.append('PACKER:GZIP')
    if re.search(r'deflatestream', param_lower):
        findings.append('PACKER:DEFLATE')

    # Multi-layer encoding: FromBase64String + MemoryStream + StreamReader
    has_b64 = 'frombase64string' in param_lower
    has_memstream = 'memorystream' in param_lower
    has_reader = 'streamreader' in param_lower or 'readtoend' in param_lower
    if has_b64 and has_memstream:
        findings.append('PACKER:MULTI_ENCODE')

    # Nested IEX (multiple Invoke-Expression calls)
    iex_count = len(re.findall(r'\biex\b|invoke-expression', param_lower))
    if iex_count >= 2:
        findings.append('PACKER:NESTED_IEX')

    # Custom char encoding: [char[]] array manipulation
    if re.search(r'\[char\[\]\]|%\{?\s*\[char\]\s*\$_\s*\}?', param_lower):
        findings.append('PACKER:CUSTOM_ENCODING')

    # String reversal
    if re.search(r'\[array\]::reverse|\.reverse\(\)|-join\s*\[char\[\]\]', param_lower):
        findings.append('PACKER:REVERSAL')

    # Heavy variable substitution chains
    var_count = len(re.findall(r'(get-variable|set-variable|new-variable)', param_lower))
    if var_count >= 3:
        findings.append('PACKER:VAR_SUBSTITUTION')

    # Invoke-Obfuscation signatures (random variable names with ${})
    obf_vars = len(re.findall(r'\$\{[^}]{10,}\}', param))
    if obf_vars >= 2:
        findings.append('PACKER:INVOKE_OBFUSCATION')

    # SecureString decode pattern
    if re.search(r'convertto-securestring.*-key|securestringtobstr', param_lower):
        findings.append('PACKER:SECURESTRING')

    return '|'.join(findings[:4]) if findings else ''
