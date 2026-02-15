def transform(param):
    import re
    indicators = []
    param_lower = param.lower()
    
    # Assembly loading
    if 'system.reflection.assembly' in param_lower:
        indicators.append('ASSEMBLY_LOAD')
    if 'load(' in param_lower and 'assembly' in param_lower:
        indicators.append('DYNAMIC_LOAD')
    
    # Type reflection
    if re.search(r'\[type\]|gettype\(', param, re.IGNORECASE):
        indicators.append('TYPE_REFLECTION')
    
    # Method invocation via reflection
    if re.search(r'\.invoke\(|invokemember\(', param, re.IGNORECASE):
        indicators.append('INVOKE_METHOD')
    
    # GetMethod/GetField
    if re.search(r'getmethod\(|getfield\(|getproperty\(', param, re.IGNORECASE):
        indicators.append('GET_MEMBER')
    
    # Delegate creation (used in shellcode runners)
    if re.search(r'getdelegateforcunctionpointer|marshal\.getdelegateforfunctionpointer', param, re.IGNORECASE):
        indicators.append('DELEGATE_CREATION')
    
    return '|'.join(indicators) if indicators else ''
