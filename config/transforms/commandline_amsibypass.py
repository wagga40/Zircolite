def transform(param):
    import re
    indicators = []
    param_lower = param.lower()
    
    # Direct AMSI references
    if 'amsi' in param_lower:
        indicators.append('AMSI_REF')
    
    # AmsiInitFailed bypass
    if re.search(r'amsiInitFailed', param, re.IGNORECASE):
        indicators.append('AMSI_INIT_FAILED')
    
    # amsiContext manipulation
    if re.search(r'amsiContext', param, re.IGNORECASE):
        indicators.append('AMSI_CONTEXT')
    
    # AmsiScanBuffer bypass
    if re.search(r'AmsiScanBuffer', param, re.IGNORECASE):
        indicators.append('AMSI_SCAN_BUFFER')
    
    # Common bypass patterns
    if re.search(r'\[Ref\]\.Assembly\.GetType.*AMSI', param, re.IGNORECASE):
        indicators.append('AMSI_REFLECTION')
    
    # Patching AMSI.DLL
    if re.search(r'amsi\.dll', param, re.IGNORECASE):
        indicators.append('AMSI_DLL')
    
    return '|'.join(indicators) if indicators else ''
