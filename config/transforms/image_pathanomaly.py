def transform(param):
    import re
    path_lower = param.lower().replace('\\', '/')
    findings = []

    # Temp directories
    if re.search(r'/temp/', path_lower):
        findings.append('TEMP_DIR')
    if '/windows/temp/' in path_lower:
        findings.append('WINDOWS_TEMP')

    # User profile writable locations
    if '/appdata/' in path_lower:
        if '/appdata/local/temp/' in path_lower:
            findings.append('USER_TEMP')
        else:
            findings.append('APPDATA')
    if re.search(r'/users/[^/]+/downloads/', path_lower):
        findings.append('DOWNLOADS')
    if re.search(r'/users/[^/]+/desktop/', path_lower):
        findings.append('USER_DESKTOP')
    if re.search(r'/users/[^/]+/(music|videos|pictures)/', path_lower):
        findings.append('USER_MEDIA_DIR')

    # Recycle Bin
    if '$recycle.bin' in path_lower or 'recycler' in path_lower:
        findings.append('RECYCLE_BIN')

    # Public profile
    if '/users/public/' in path_lower:
        findings.append('PUBLIC_PROFILE')

    # PerfLogs (commonly used for staging)
    if '/perflogs/' in path_lower:
        findings.append('PERFLOGS')

    return '|'.join(findings[:3]) if findings else ''
