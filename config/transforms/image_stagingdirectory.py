def transform(param):
    import re
    path_lower = param.lower().replace('\\', '/')
    findings = []

    # ProgramData (very common staging)
    if '/programdata/' in path_lower:
        findings.append('STAGING:ProgramData')

    # Windows Temp
    if '/windows/temp/' in path_lower:
        findings.append('STAGING:WindowsTemp')

    # Root-level Temp
    if re.match(r'^[a-z]:/temp/', path_lower):
        findings.append('STAGING:RootTemp')

    # PerfLogs
    if '/perflogs/' in path_lower:
        findings.append('STAGING:PerfLogs')

    # Vendor-named folders abused for blending in
    vendor_dirs = ['/intel/', '/dell/', '/hp/', '/lenovo/', '/nvidia/']
    for vd in vendor_dirs:
        if vd in path_lower and '/program files' not in path_lower:
            findings.append('STAGING:VendorFolder')
            break

    # Public profile
    if '/users/public/' in path_lower:
        findings.append('STAGING:PublicProfile')

    # Recycle Bin
    if '$recycle.bin' in path_lower:
        findings.append('STAGING:RecycleBin')

    # UNC temp paths
    if re.match(r'^//', path_lower) or path_lower.startswith('\\\\'):
        findings.append('STAGING:UNC_Path')

    # /tmp on Linux
    if path_lower.startswith('/tmp/') or path_lower.startswith('/var/tmp/'):
        findings.append('STAGING:LinuxTmp')

    # /dev/shm (memory-backed, common for fileless)
    if path_lower.startswith('/dev/shm/'):
        findings.append('STAGING:DevShm')

    return '|'.join(findings[:3]) if findings else ''
