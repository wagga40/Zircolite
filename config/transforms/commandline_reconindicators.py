def transform(param):
    import re
    findings = []
    param_lower = param.lower()

    # System information
    if re.search(r'\bsysteminfo\b|\bhostname\b|\bver\b$|\buname\s+-a\b', param_lower):
        findings.append('RECON:SYSINFO')

    # Network reconnaissance
    if re.search(r'\bipconfig\b|\bifconfig\b|\bnetstat\b|\barp\s+-a\b|\broute\s+print\b|\bnslookup\b|\btracert\b|\btraceroute\b', param_lower):
        findings.append('RECON:NETWORK')

    # User and group enumeration
    if re.search(r'\bwhoami\b|\bnet\s+user\b|\bnet\s+group\b|\bnet\s+localgroup\b|\b(id|groups)\s', param_lower):
        findings.append('RECON:USER_ENUM')

    # Domain reconnaissance
    if re.search(r'nltest\s+/dclist|dsquery|gpresult|adfind|ldapsearch|get-addomain|get-adforest', param_lower):
        findings.append('RECON:DOMAIN')

    # Share enumeration
    if re.search(r'\bnet\s+share\b|\bnet\s+view\b', param_lower):
        findings.append('RECON:SHARE')

    # Process enumeration
    if re.search(r'\btasklist\b|wmic\s+process|get-process\b|\bps\s+aux\b', param_lower):
        findings.append('RECON:PROCESS')

    # Security tool enumeration
    if re.search(r'netsh\s+advfirewall|get-mppreference|wmic.*antivirusproduct|get-mpcomputerstatus', param_lower):
        findings.append('RECON:SECURITY')

    return '|'.join(findings[:3]) if findings else ''
