def transform(param):
    import re
    suspicious = []
    param_lower = param.lower()
    
    # Run keys (persistence)
    if re.search(r'\\run\\|\\runonce\\', param, re.IGNORECASE):
        suspicious.append('RUN_KEY')
    
    # Services (persistence)
    if re.search(r'\\services\\', param, re.IGNORECASE):
        suspicious.append('SERVICE_KEY')
    
    # Image File Execution Options (hijacking)
    if 'image file execution options' in param_lower:
        suspicious.append('IFEO')
    
    # AppInit DLLs
    if 'appinit_dlls' in param_lower:
        suspicious.append('APPINIT_DLLS')
    
    # Winlogon (persistence)
    if 'winlogon' in param_lower:
        suspicious.append('WINLOGON')
    
    # COM hijacking
    if re.search(r'\\clsid\\|\\inprocserver', param, re.IGNORECASE):
        suspicious.append('COM_HIJACK')
    
    # Scheduled tasks
    if 'schedule\\taskcache' in param_lower:
        suspicious.append('SCHED_TASK')
    
    # Security settings
    if re.search(r'\\policies\\|\\security\\', param, re.IGNORECASE):
        suspicious.append('SECURITY_POLICY')
    
    return '|'.join(suspicious) if suspicious else ''
