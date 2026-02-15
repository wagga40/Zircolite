def transform(param):
    import re
    findings = []
    param_lower = param.lower()

    # Classic remote thread injection
    if re.search(r'createremotethread|ntcreatethread', param_lower):
        findings.append('INJECT:CLASSIC')

    # Memory allocation + write (injection setup)
    if re.search(r'virtualallocex', param_lower) and re.search(r'writeprocessmemory', param_lower):
        findings.append('INJECT:ALLOC_WRITE')

    # Process hollowing
    if re.search(r'create_suspended|ntunmapviewofsection|zwunmapviewofsection', param_lower):
        findings.append('INJECT:HOLLOWING')

    # APC injection
    if re.search(r'queueuserapc|ntqueueapcthread', param_lower):
        findings.append('INJECT:APC')

    # Thread hijacking
    if re.search(r'suspendthread.*setthreadcontext|getthreadcontext.*setthreadcontext', param_lower):
        findings.append('INJECT:THREAD_HIJACK')

    # Callback-based injection
    if re.search(r'enumwindows|createtimerqueuetimer|setwindowshookex', param_lower):
        findings.append('INJECT:CALLBACK')

    # Section mapping injection
    if re.search(r'ntcreatesection.*ntmapviewofsection', param_lower):
        findings.append('INJECT:MAPPING')

    # ETW bypass (often paired with injection)
    if re.search(r'ntwritevirtualmemory.*etweventwrite|etweventwrite.*patch', param_lower):
        findings.append('INJECT:ETW_BYPASS')

    # Generic VirtualAlloc + shellcode indicators
    if re.search(r'virtualalloc.*marshal\.copy|virtualalloc.*\[byte\[\]\]', param_lower):
        findings.append('INJECT:SHELLCODE_ALLOC')

    return '|'.join(findings[:3]) if findings else ''
