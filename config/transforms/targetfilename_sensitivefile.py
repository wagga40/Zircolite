def transform(param):
    import re
    findings = []
    name_lower = param.lower().replace('\\', '/')

    # Credential stores
    cred_files = ['sam', 'system', 'security', 'ntds.dit', 'shadow', 'passwd',
                  '.kdbx', '.keychain', 'secrets.ldb', 'secrets.tdb']
    for cf in cred_files:
        if cf in name_lower.split('/')[-1] if '/' in name_lower else cf in name_lower:
            findings.append('SENSITIVE:CREDENTIAL_STORE')
            break

    # NTDS.dit specific path
    if 'ntds.dit' in name_lower:
        findings.append('SENSITIVE:NTDS')

    # SSH keys
    ssh_files = ['id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa',
                 'known_hosts', 'authorized_keys', '.ssh/config']
    for sf in ssh_files:
        if sf in name_lower:
            findings.append('SENSITIVE:SSH_KEY')
            break

    # Private certificates
    if re.search(r'\.(pfx|p12|pem|key)$', name_lower):
        findings.append('SENSITIVE:CERT_PRIVATE')

    # Browser credential data
    browser_files = ['login data', 'cookies', 'web data', 'logins.json',
                     'signons.sqlite', 'key3.db', 'key4.db', 'cert9.db']
    for bf in browser_files:
        if bf in name_lower:
            findings.append('SENSITIVE:BROWSER_DATA')
            break

    # Config files with secrets
    config_files = ['web.config', '.env', 'wp-config.php', 'credentials.xml',
                    'unattend.xml', 'sysprep.xml', '.git-credentials',
                    'appsettings.json', 'connectionstrings.config']
    for cf in config_files:
        if cf in name_lower:
            findings.append('SENSITIVE:CONFIG')
            break

    # Memory dumps
    if re.search(r'lsass.*\.dmp|\.hdmp$|procdump', name_lower):
        findings.append('SENSITIVE:MEMORY_DUMP')

    return '|'.join(findings[:3]) if findings else ''
