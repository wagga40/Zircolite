def transform(param):
    import re
    # Extract filename from path
    name = param.replace('\\', '/').split('/')[-1]
    # Match pattern: .normalext.executableext
    match = re.search(
        r'\.(\w{2,5})\.(exe|scr|bat|cmd|com|pif|vbs|vbe|js|jse|wsh|wsf|ps1|msi|dll|hta|cpl)$',
        name, re.IGNORECASE
    )
    if match:
        return 'DOUBLE_EXT:' + match.group(1) + '.' + match.group(2).lower()
    return ''
