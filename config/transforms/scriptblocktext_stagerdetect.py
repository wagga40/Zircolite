def transform(param):
    import re
    findings = []
    param_lower = param.lower()

    # Reflection-based assembly loading
    if re.search(r'\[system\.reflection\.assembly\]::load|\[reflection\.assembly\]::load', param_lower):
        findings.append('STAGER:REFLECTION_LOAD')

    # Staged IEX with download
    if re.search(r'iex\s*\(.*new-object\s+net\.webclient', param_lower):
        findings.append('STAGER:STAGED_IEX')
    if re.search(r'invoke-expression.*invoke-webrequest|iex.*iwr|iex.*invoke-restmethod', param_lower):
        findings.append('STAGER:STAGED_IEX')

    # In-memory .NET loading
    if re.search(r'frombase64string.*\.load\(|\.load\(.*frombase64string', param_lower):
        findings.append('STAGER:INMEMORY_NET')

    # AMSI bypass followed by execution
    if re.search(r'amsi', param_lower) and re.search(r'iex|invoke-expression|\.invoke\(', param_lower):
        findings.append('STAGER:AMSI_THEN_EXEC')

    # AppDomain abuse
    if re.search(r'appdomain\.currentdomain|definedynamicassembly|definedynamicmodule', param_lower):
        findings.append('STAGER:APPDOMAIN')

    # Runspace abuse (PowerShell-in-PowerShell)
    if re.search(r'\[powershell\]::create\(\)|addscript.*begininvoke|runspacefactory', param_lower):
        findings.append('STAGER:RUNSPACE')

    # Constrained Language Mode bypass
    if re.search(r'languagemode.*fulllanguage|fulllanguagemode', param_lower):
        findings.append('STAGER:CLM_BYPASS')

    # Win32 API direct calls via Add-Type
    if re.search(r'add-type.*dllimport.*kernel32|add-type.*dllimport.*ntdll', param_lower):
        findings.append('STAGER:WIN32_API')

    return '|'.join(findings[:3]) if findings else ''
