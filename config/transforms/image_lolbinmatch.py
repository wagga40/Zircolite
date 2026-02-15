def transform(param):
    lolbins = [
        'certutil', 'mshta', 'regsvr32', 'rundll32', 'wmic',
        'cscript', 'wscript', 'powershell', 'cmd', 'msiexec',
        'installutil', 'regasm', 'regsvcs', 'msconfig', 'msbuild',
        'cmstp', 'certreq', 'dnscmd', 'eudcedit', 'expand',
        'extrac32', 'findstr', 'forfiles', 'ftp', 'gpscript',
        'hh', 'ieexec', 'infdefaultinstall', 'makecab', 'mavinject',
        'pcalua', 'pcwrun', 'presentationhost', 'replace', 'rpcping',
        'runscripthelper', 'syncappvpublishingserver', 'control',
        'bash', 'bitsadmin'
    ]
    exe_name = param.replace('\\', '/').split('/')[-1].lower()
    exe_name = exe_name.replace('.exe', '')
    if exe_name in lolbins:
        return 'LOLBIN:' + exe_name
    return ''
