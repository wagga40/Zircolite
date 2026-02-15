def transform(param):
    import re
    path_lower = param.lower().replace('\\', '/')

    # Map of critical process names to their expected directory patterns
    # Format: exe_name -> list of allowed path patterns
    expected_paths = {
        'svchost.exe': ['/windows/system32/'],
        'csrss.exe': ['/windows/system32/'],
        'lsass.exe': ['/windows/system32/'],
        'services.exe': ['/windows/system32/'],
        'smss.exe': ['/windows/system32/'],
        'wininit.exe': ['/windows/system32/'],
        'winlogon.exe': ['/windows/system32/'],
        'spoolsv.exe': ['/windows/system32/'],
        'taskhost.exe': ['/windows/system32/'],
        'taskhostw.exe': ['/windows/system32/'],
        'runtimebroker.exe': ['/windows/system32/'],
        'explorer.exe': ['/windows/'],
        'dllhost.exe': ['/windows/system32/', '/windows/syswow64/'],
        'lsm.exe': ['/windows/system32/'],
        'conhost.exe': ['/windows/system32/'],
        'dwm.exe': ['/windows/system32/'],
        'sihost.exe': ['/windows/system32/'],
        'fontdrvhost.exe': ['/windows/system32/'],
    }

    # Extract exe name from full path
    parts = path_lower.split('/')
    exe_name = parts[-1] if parts else ''

    if exe_name in expected_paths:
        allowed = expected_paths[exe_name]
        in_allowed = False
        for allowed_path in allowed:
            if allowed_path in path_lower:
                in_allowed = True
                break
        if not in_allowed and len(path_lower) > len(exe_name):
            return 'MASQUERADE:' + exe_name
    return ''
