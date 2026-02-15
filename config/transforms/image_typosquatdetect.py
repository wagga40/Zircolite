def transform(param):
    # High-value targets for typosquatting detection
    # These are processes attackers commonly impersonate
    typosquat_targets = [
        # Critical Windows processes (most commonly impersonated)
        'svchost', 'services', 'lsass', 'csrss', 'smss', 'wininit',
        'winlogon', 'explorer', 'taskhost', 'taskhostw', 'dwm',
        'conhost', 'dllhost', 'spoolsv', 'searchindexer', 'wmiprvse',
        # LOLBins (commonly abused)
        'powershell', 'cmd', 'rundll32', 'regsvr32', 'mshta', 'wmic',
        'cscript', 'wscript', 'msiexec', 'certutil', 'bitsadmin',
        # Browsers
        'chrome', 'firefox', 'msedge', 'iexplore',
        # Apps
        'outlook', 'teams', 'onedrive', 'dropbox',
    ]
    
    # Comprehensive whitelist of legitimate Windows executables
    # These will NEVER be flagged as typosquats
    legit_whitelist = set([
        # System utilities with similar names (false positive prevention)
        'wevtutil', 'vssadmin', 'netstat', 'nbtstat', 'pathping',
        'tracert', 'ipconfig', 'netsh', 'schtasks', 'tasklist',
        'taskkill', 'systeminfo', 'hostname', 'whoami', 'quser',
        'qwinsta', 'query', 'logoff', 'shutdown', 'gpupdate',
        'gpresult', 'auditpol', 'secedit', 'icacls', 'takeown',
        'cacls', 'attrib', 'cipher', 'compact', 'expand',
        'makecab', 'extrac32', 'fsutil', 'diskpart', 'diskperf',
        'chkdsk', 'chkntfs', 'defrag', 'sfc', 'dism', 'bcdedit',
        'bootcfg', 'msinfo32', 'perfmon', 'resmon', 'eventvwr',
        'compmgmt', 'devmgmt', 'diskmgmt', 'services', 'taskschd',
        'lusrmgr', 'secpol', 'gpedit', 'regedit', 'regedt32',
        # PowerShell variants
        'powershell', 'pwsh', 'powershell_ise',
        # CMD variants
        'cmd', 'command',
        # Windows services and hosts
        'svchost', 'taskhost', 'taskhostw', 'dllhost', 'conhost',
        'RuntimeBroker', 'smartscreen', 'fontdrvhost', 'sihost',
        'ctfmon', 'dwm', 'winlogon', 'wininit', 'csrss', 'smss',
        'lsass', 'lsm', 'services', 'spoolsv', 'wuauclt', 'trustedinstaller',
        # Microsoft Office
        'winword', 'excel', 'powerpnt', 'outlook', 'onenote', 'msaccess',
        'mspub', 'visio', 'lync', 'teams',
        # Browsers and updaters
        'chrome', 'firefox', 'msedge', 'iexplore', 'opera', 'brave',
        'chromium', 'vivaldi', 'update', 'updater', 'googleupdate',
        # Security tools
        'defender', 'msmpeng', 'nissrv', 'mpcmdrun', 'malwarebytes',
        'mbam', 'avast', 'avgui', 'norton', 'nortonsecurity',
        # Common apps
        'onedrive', 'dropbox', 'slack', 'zoom', 'skype', 'discord',
        'spotify', 'steam', 'vlc', 'notepad', 'notepad++', 'calc',
        'mspaint', 'wordpad', 'write', 'charmap', 'magnify', 'narrator',
        # Development tools
        'code', 'devenv', 'msbuild', 'vscode', 'git', 'node', 'python',
        'java', 'javaw', 'dotnet', 'nuget',
        # Network tools
        'ping', 'nslookup', 'dig', 'curl', 'wget', 'ssh', 'scp', 'sftp',
        'ftp', 'telnet', 'putty', 'plink', 'pscp', 'psftp',
        # All typosquat targets are also legitimate
    ] + typosquat_targets)
    
    # Simple edit distance calculation (Levenshtein-like)
    def edit_distance(s1, s2):
        if len(s1) < len(s2):
            return edit_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]
    
    # Extract exe name
    exe_name = param.replace('\\', '/').split('/')[-1].lower()
    exe_name = exe_name.replace('.exe', '').replace('.com', '').replace('.scr', '')
    
    if not exe_name or len(exe_name) < 4:
        return ''
    
    # IMPORTANT: Skip if exe_name is a known legitimate executable
    # This prevents false positives like wevtutil being flagged as certutil
    if exe_name in legit_whitelist:
        return ''
    
    findings = []
    for target in typosquat_targets:
        # Skip very short names to avoid false positives
        if len(target) < 5:
            continue
        
        dist = edit_distance(exe_name, target)
        
        # Require higher similarity for detection
        # Only flag if edit distance is 1-2 AND represents significant % of name
        max_dist = 1 if len(target) <= 7 else 2
        
        if 0 < dist <= max_dist:
            # Additional validation: require suspicious character patterns
            # to reduce false positives
            is_suspicious = False
            patterns = []
            
            # Homoglyph substitution (l->1, o->0, etc.)
            if any(c in exe_name for c in '01'):
                for i, c in enumerate(exe_name):
                    if c == '0' and i < len(target) and target[i] == 'o':
                        is_suspicious = True
                        patterns.append('HOMOGLYPH')
                        break
                    if c == '1' and i < len(target) and target[i] in 'li':
                        is_suspicious = True
                        patterns.append('HOMOGLYPH')
                        break
            
            # rn -> m substitution
            if 'rn' in exe_name and 'm' in target:
                is_suspicious = True
                patterns.append('HOMOGLYPH')
            
            # vv -> w substitution  
            if 'vv' in exe_name and 'w' in target:
                is_suspicious = True
                patterns.append('HOMOGLYPH')
            
            # Character omission/addition at beginning or end
            if abs(len(exe_name) - len(target)) == 1:
                if exe_name.startswith(target) or exe_name.endswith(target):
                    is_suspicious = True
                    patterns.append('CHAR_ADD')
                elif target.startswith(exe_name) or target.endswith(exe_name):
                    is_suspicious = True
                    patterns.append('CHAR_OMIT')
            
            # Single char substitution in middle of name
            if len(exe_name) == len(target) and dist == 1:
                is_suspicious = True
                if not patterns:
                    patterns.append('CHAR_SWAP')
            
            # Only report if we found suspicious patterns
            if is_suspicious:
                pattern_str = ','.join(patterns) if patterns else 'SIMILAR'
                findings.append(f'TYPOSQUAT:{target}({pattern_str})')
    
    return '|'.join(findings[:2]) if findings else ''  # Limit output
