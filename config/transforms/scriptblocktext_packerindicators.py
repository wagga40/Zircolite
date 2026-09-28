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

    # Invoke-Obfuscation signatures (random variable names with ${}).
    # Counts what re.findall(r'\$\{[^}]{10,}\}', param) would, in linear
    # time: a '${' can only close at the next '}', and every '${' before
    # that '}' has a shorter body, so the scan resumes after it. The regex
    # form scans to the end of the input from every '${' when there is no
    # '}', which is quadratic on '${${${...'.
    obf_vars = 0
    pos = 0
    while obf_vars < 2:
        var_open = param.find('${', pos)
        if var_open == -1:
            break
        var_close = param.find('}', var_open + 2)
        if var_close == -1:
            break
        if var_close - var_open - 2 >= 10:
            obf_vars += 1
        pos = var_close + 1
    if obf_vars >= 2:
        findings.append('PACKER:INVOKE_OBFUSCATION')

    # SecureString decode pattern: re.search('convertto-securestring.*-key')
    # line by line, so that each line is scanned once rather than once per
    # 'convertto-securestring' in it
    secure_key = False
    for line in param_lower.split('\n'):
        secure_start = line.find('convertto-securestring')
        if secure_start != -1 and line.find('-key', secure_start + 22) != -1:
            secure_key = True
            break
    if secure_key or 'securestringtobstr' in param_lower:
        findings.append('PACKER:SECURESTRING')

    return '|'.join(findings[:4]) if findings else ''
