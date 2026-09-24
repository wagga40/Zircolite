def transform(param):
    import re
    findings = []
    param_lower = param.lower()

    def in_order(text, patterns, flags=0):
        # Same answer as re.search('p0.*p1.*p2', text, flags), in linear
        # time. The regex form retries every p0 and rescans to the end of
        # the line from each, which is quadratic (cubic with three steps) on
        # crafted input. Here each pattern's matches are found once, in order.
        # '.' stops at a newline, so each later pattern must start on the
        # line the previous match ended on. A p0 match that ends on the same
        # line as an earlier one that failed can only fail too. p1 and p2 are
        # plain tokens, so their leftmost match on the line is the best one.
        compiled = [re.compile(p, flags) for p in patterns]
        searched_from = [-1] * len(compiled)
        found = [None] * len(compiled)
        newline = [-1, -1]

        def first(i, pos):
            # Leftmost match of pattern i at or after pos.
            hit = found[i]
            if searched_from[i] != -1 and searched_from[i] <= pos and (hit is None or hit.start() >= pos):
                return hit
            hit = compiled[i].search(text, pos)
            searched_from[i] = pos
            found[i] = hit
            return hit

        def line_end(pos):
            # Index of the first newline at or after pos, or len(text).
            if newline[0] != -1 and newline[0] <= pos <= newline[1]:
                return newline[1]
            end = text.find('\n', pos)
            if end == -1:
                end = len(text)
            newline[0] = pos
            newline[1] = end
            return end

        pos = 0
        last_end = -1
        failed_line = -1
        while True:
            start = compiled[0].search(text, pos)
            if start is None:
                return False
            pos = start.start() + 1
            if last_end <= start.end() <= failed_line:
                continue
            last_end = start.end()
            end = start.end()
            matched = True
            for i in range(1, len(compiled)):
                hit = first(i, end)
                if hit is None or hit.start() > line_end(end):
                    matched = False
                    break
                end = hit.end()
            if matched:
                return True
            failed_line = line_end(start.end())

    # Scheduled tasks
    if re.search(r'schtasks\s+/create|new-scheduledtask|register-scheduledjob', param_lower):
        findings.append('PERSIST:SCHED_TASK')

    # Services
    if re.search(r'sc\s+(create|config)\s|new-service\s|sc\.exe\s+(create|config)', param_lower):
        findings.append('PERSIST:SERVICE')

    # Registry Run keys
    if in_order(param_lower, [r'(reg\s+add|set-itemproperty|new-itemproperty)', r'\\(run|runonce)\b']):
        findings.append('PERSIST:REG_RUN')

    # WMI event subscriptions
    if re.search(r'__eventfilter|commandlineeventconsumer|__filtertoconsumerbinding|set-wmiinstance', param_lower):
        findings.append('PERSIST:WMI_SUB')

    # Startup folder
    if (re.search(r'shell:startup|start menu\\programs\\startup', param_lower)
            or in_order(param_lower, [r'\.lnk', 'startup'])):
        findings.append('PERSIST:STARTUP_FOLDER')

    # DLL search order / path hijacking
    if in_order(param_lower, [r'(reg\s+add|set-itemproperty)', r'\\environment\\', 'path']):
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
