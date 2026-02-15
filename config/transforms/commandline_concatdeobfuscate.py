def transform(param):
    import re
    findings = []

    # CMD caret escaping: p^ow^er^sh^ell -> powershell
    if '^' in param:
        deobf = param.replace('^', '')
        if deobf != param:
            # Extract notable keywords from deobfuscated string
            for kw in ['powershell', 'cmd', 'invoke', 'download', 'iex', 'bypass', 'hidden']:
                if kw in deobf.lower() and kw not in param.lower().replace('^', ''):
                    pass  # caret was between letters of keyword
            cleaned = re.sub(r'\s+', ' ', deobf).strip()
            if len(cleaned) > 5 and cleaned != param:
                findings.append('DEOBF:CARET')

    # PowerShell string concatenation: 'po'+'wer'+'shell'
    concat_match = re.findall(r"'([^']+)'\s*\+\s*'([^']+)'", param)
    if concat_match:
        reconstructed = ''
        for m in concat_match:
            reconstructed += m[0] + m[1]
        if reconstructed:
            findings.append('DEOBF:CONCAT:' + reconstructed[:50])

    # PowerShell format operator: '{0}{1}'-f'power','shell'
    fmt_match = re.search(r"'(\{[0-9]+\}[^']*)'?\s*-f\s*'([^']+)'(?:\s*,\s*'([^']+)')*", param)
    if fmt_match:
        findings.append('DEOBF:FORMAT_OP')

    # Backtick escaping: pow`er`shell
    if '`' in param:
        deobf = re.sub(r'`([a-zA-Z])', r'\1', param)
        if deobf != param:
            findings.append('DEOBF:BACKTICK')

    # CMD env variable substring abuse: %COMSPEC:~0,1%
    if re.search(r'%[^%]+:~\d+,\d+%', param):
        findings.append('DEOBF:ENV_SUBSTR')

    return '|'.join(findings[:3]) if findings else ''
