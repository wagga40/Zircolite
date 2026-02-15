def transform(param):
    import re
    parent_lower = param.lower().replace('\\', '/').split('/')[-1]
    parent_lower = parent_lower.replace('.exe', '')
    findings = []

    # Office applications spawning children
    office_apps = ['winword', 'excel', 'powerpnt', 'outlook', 'msaccess',
                   'mspub', 'visio', 'onenote', 'eqnedt32']
    if parent_lower in office_apps:
        findings.append('ANOMALY:OFFICE_SPAWN')

    # Browser spawning children
    browsers = ['chrome', 'firefox', 'msedge', 'iexplore', 'opera', 'brave']
    if parent_lower in browsers:
        findings.append('ANOMALY:BROWSER_SPAWN')

    # PDF readers spawning children
    pdf_apps = ['acrord32', 'acrobat', 'foxitreader', 'foxitphantom',
                'sumatrapdf']
    if parent_lower in pdf_apps:
        findings.append('ANOMALY:PDF_SPAWN')

    # Script engines as parents (chaining)
    script_engines = ['wscript', 'cscript', 'mshta']
    if parent_lower in script_engines:
        findings.append('ANOMALY:SCRIPT_CHAIN')

    # WMI provider host as parent
    if parent_lower in ['wmiprvse', 'wmiprvse.exe']:
        findings.append('ANOMALY:WMI_SPAWN')

    # Task scheduler engine
    if parent_lower in ['taskeng', 'taskhostw']:
        findings.append('ANOMALY:TASK_SPAWN')

    # Java spawning children (exploit indicator)
    if parent_lower in ['java', 'javaw', 'javaws']:
        findings.append('ANOMALY:JAVA_SPAWN')

    return '|'.join(findings[:2]) if findings else ''
