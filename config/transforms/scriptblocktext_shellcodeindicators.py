def transform(param):
    import re
    indicators = []
    param_lower = param.lower()
    
    # VirtualAlloc with executable permissions
    if re.search(r'virtualalloc.*0x40|virtualalloc.*page_execute', param, re.IGNORECASE):
        indicators.append('EXEC_MEMORY_ALLOC')
    
    # Kernel32/ntdll function calls
    if 'kernel32' in param_lower:
        indicators.append('KERNEL32_REF')
    if 'ntdll' in param_lower:
        indicators.append('NTDLL_REF')
    
    # CreateThread/CreateRemoteThread
    if 'createthread' in param_lower:
        indicators.append('CREATE_THREAD')
    
    # Shellcode byte patterns (common NOP sled, syscall patterns)
    if re.search(r'0x90,\s*0x90|\\x90\\x90', param):
        indicators.append('NOP_SLED')
    
    # Copy memory operations
    if re.search(r'marshal\.copy|rtlmovememory|copymemory', param, re.IGNORECASE):
        indicators.append('MEMORY_COPY')
    
    # Pointer operations
    if re.search(r'intptr|marshal\.allochglobal', param, re.IGNORECASE):
        indicators.append('POINTER_OP')
    
    return '|'.join(indicators) if indicators else ''
