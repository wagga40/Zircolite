def transform(param):
    import re
    findings = []
    param_lower = param.lower()

    # PsExec
    if re.search(r'psexec|paexec', param_lower):
        findings.append('LATERAL:PSEXEC')

    # Remote service control
    if re.search(r'sc\s+\\\\[^\s]+\s+(create|start|config|query)', param_lower):
        findings.append('LATERAL:REMOTE_SERVICE')

    # WMI remote
    if re.search(r'wmic\s+/node:|invoke-wmimethod|invoke-cimmethod', param_lower):
        findings.append('LATERAL:WMI')

    # WinRM / PowerShell remoting
    if re.search(r'enter-pssession|invoke-command\s+.*-computername|winrs\s+', param_lower):
        findings.append('LATERAL:WINRM')

    # RDP
    if re.search(r'mstsc\s+/v:|cmdkey\s+/add:', param_lower):
        findings.append('LATERAL:RDP')

    # SMB file operations to remote hosts
    if re.search(r'(net\s+use|copy|move|xcopy|robocopy)\s+\\\\', param_lower):
        findings.append('LATERAL:SMB')

    # SSH/SCP lateral
    if re.search(r'\bssh\s+.*@|\bscp\s+.*:|plink\s+', param_lower):
        findings.append('LATERAL:SSH')

    # DCOM
    if re.search(r'mmc20\.application|shellwindows|shellbrowserwindow', param_lower):
        findings.append('LATERAL:DCOM')

    # at command remote
    if re.search(r'\bat\s+\\\\', param_lower):
        findings.append('LATERAL:AT_REMOTE')

    return '|'.join(findings[:3]) if findings else ''
