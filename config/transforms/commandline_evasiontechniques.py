def transform(param):
    import re
    indicators = []
    param_lower = param.lower()
    
    # Process hollowing indicators
    if 'ntunmapviewofsection' in param_lower or 'zwunmapviewofsection' in param_lower:
        indicators.append('PROCESS_HOLLOWING')
    
    # Reflective DLL injection
    if 'reflectiveloader' in param_lower:
        indicators.append('REFLECTIVE_DLL')
    
    # Token manipulation
    if 'adjusttokenprivileges' in param_lower or 'setthreadtoken' in param_lower:
        indicators.append('TOKEN_MANIPULATION')
    
    # Memory allocation (VirtualAlloc, etc.)
    if re.search(r'virtualalloc|ntalloc|zwalloc', param, re.IGNORECASE):
        indicators.append('MEMORY_ALLOC')
    
    # CreateRemoteThread
    if 'createremotethread' in param_lower:
        indicators.append('REMOTE_THREAD')
    
    # Syscall direct invocation
    if re.search(r'\bsyscall\b|ntdll', param, re.IGNORECASE):
        indicators.append('SYSCALL')
    
    # ETW bypass
    if re.search(r'etw|nttracevent', param, re.IGNORECASE):
        indicators.append('ETW_BYPASS')
    
    return '|'.join(indicators) if indicators else ''
