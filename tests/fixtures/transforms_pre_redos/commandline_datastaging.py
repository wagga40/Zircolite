def transform(param):
    import re
    findings = []
    param_lower = param.lower()

    # Archiving / compression
    if re.search(r'\brar\s+a\b|7z\s+a\b|\bzip\b.*-r|tar\s+(-czf|-cf|--create)|makecab|compact\s+/c', param_lower):
        findings.append('STAGING:ARCHIVE')

    # Bulk copy operations
    if re.search(r'\brobocopy\b|\bxcopy\b.*(/s|/e)|\bcopy\b.*\*\.', param_lower):
        findings.append('STAGING:BULK_COPY')

    # Database dumps
    if re.search(r'sqlcmd\s+.*-[Qq]|mysqldump|pg_dump|sqlite3\s+.*\.dump', param_lower):
        findings.append('STAGING:DB_DUMP')

    # Email collection (.pst, .ost)
    if re.search(r'\.(pst|ost)\b', param_lower):
        findings.append('STAGING:EMAIL_COLLECT')

    # Sensitive file hunting
    if re.search(r'(findstr|dir|find|ls|get-childitem).*\.(docx?|xlsx?|pptx?|pdf|kdbx|key|pem)', param_lower):
        findings.append('STAGING:FILE_HUNT')

    # ntdsutil / active directory dumping
    if re.search(r'ntdsutil|secretsdump|dcsync', param_lower):
        findings.append('STAGING:AD_DUMP')

    return '|'.join(findings[:3]) if findings else ''
