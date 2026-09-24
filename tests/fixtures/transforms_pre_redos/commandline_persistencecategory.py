def transform(param):
    import re
    findings = []
    param_lower = param.lower()

    # Scheduled tasks
    if re.search(r'schtasks\s+/create|new-scheduledtask|register-scheduledjob', param_lower):
        findings.append('PERSIST:SCHED_TASK')

    # Services
    if re.search(r'sc\s+(create|config)\s|new-service\s|sc\.exe\s+(create|config)', param_lower):
        findings.append('PERSIST:SERVICE')

    # Registry Run keys
    if re.search(r'(reg\s+add|set-itemproperty|new-itemproperty).*\\(run|runonce)\b', param_lower):
        findings.append('PERSIST:REG_RUN')

    # WMI event subscriptions
    if re.search(r'__eventfilter|commandlineeventconsumer|__filtertoconsumerbinding|set-wmiinstance', param_lower):
        findings.append('PERSIST:WMI_SUB')

    # Startup folder
    if re.search(r'shell:startup|start menu\\programs\\startup|\.lnk.*startup', param_lower):
        findings.append('PERSIST:STARTUP_FOLDER')

    # DLL search order / path hijacking
    if re.search(r'(reg\s+add|set-itemproperty).*\\environment\\.*path', param_lower):
        findings.append('PERSIST:DLL_SEARCH')

    # Cron (Linux)
    if re.search(r'crontab\s+-[ei]|/etc/cron\.|/var/spool/cron', param_lower):
        findings.append('PERSIST:CRON')

    # Systemd (Linux)
    if re.search(r'systemctl\s+(enable|daemon-reload)|/etc/systemd/', param_lower):
        findings.append('PERSIST:SYSTEMD')

    # Launch Agent/Daemon (macOS)
    if re.search(r'launchagent|launchdaemon|com\.apple\.loginitems|/library/launch', param_lower):
        findings.append('PERSIST:LAUNCH_AGENT')

    # Boot/logon autostart
    if re.search(r'bcdedit\s+/set|bootexecute', param_lower):
        findings.append('PERSIST:BOOT')

    return '|'.join(findings[:3]) if findings else ''
