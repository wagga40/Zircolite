def transform(param):
    import re
    findings = []
    param_lower = param.lower()

    # Cobalt Strike
    cs_indicators = [
        r'\bbeacon\b', r'\bspawn(to|as|x64|x86)\b',
        r'\\\\\.\\pipe\\msagent_', r'\\\\\.\\pipe\\postex_',
        r'/pixel[^a-z]|/submit\.php|/__utm\.gif|/activity',
        r'jump\s+(psexec|winrm|ssh)',
    ]
    for pat in cs_indicators:
        if re.search(pat, param_lower):
            findings.append('C2:COBALT_STRIKE')
            break

    # Metasploit / Meterpreter
    if re.search(r'meterpreter|multi/handler|exploit/|payload/|msfvenom|msfconsole|lhost\s*=|lport\s*=', param_lower):
        findings.append('C2:METASPLOIT')

    # Sliver
    if re.search(r'\bsliver\b|implant.*generate|mtls\s|wg\s.*listener', param_lower):
        findings.append('C2:SLIVER')

    # Empire / Starkiller
    if re.search(r'\blauncher\b.*\bstager\b|invoke-empire|starfighters|starkiller', param_lower):
        findings.append('C2:EMPIRE')

    # Havoc
    if re.search(r'\bdemon\b.*\bhavoc\b|havoc\s+.*listener', param_lower):
        findings.append('C2:HAVOC')

    # Generic named pipe patterns (common in C2)
    if re.search(r'\\\\\.\\pipe\\[a-f0-9]{8}-[a-f0-9]{4}', param_lower):
        findings.append('C2:GENERIC_PIPE')

    # Covenant / Grunt
    if re.search(r'\bgrunt\b.*\bcovenant\b|grunt(http|smb)', param_lower):
        findings.append('C2:COVENANT')

    return '|'.join(findings[:3]) if findings else ''
