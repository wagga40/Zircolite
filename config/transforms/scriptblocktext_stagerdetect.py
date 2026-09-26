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

    # Reflection-based assembly loading
    if re.search(r'\[system\.reflection\.assembly\]::load|\[reflection\.assembly\]::load', param_lower):
        findings.append('STAGER:REFLECTION_LOAD')

    # Staged IEX with download
    if in_order(param_lower, [r'iex\s*\(', r'new-object\s+net\.webclient']):
        findings.append('STAGER:STAGED_IEX')
    if (in_order(param_lower, ['invoke-expression', 'invoke-webrequest'])
            or in_order(param_lower, ['iex', 'iwr'])
            or in_order(param_lower, ['iex', 'invoke-restmethod'])):
        findings.append('STAGER:STAGED_IEX')

    # In-memory .NET loading
    if (in_order(param_lower, ['frombase64string', r'\.load\('])
            or in_order(param_lower, [r'\.load\(', 'frombase64string'])):
        findings.append('STAGER:INMEMORY_NET')

    # AMSI bypass followed by execution
    if re.search(r'amsi', param_lower) and re.search(r'iex|invoke-expression|\.invoke\(', param_lower):
        findings.append('STAGER:AMSI_THEN_EXEC')

    # AppDomain abuse
    if re.search(r'appdomain\.currentdomain|definedynamicassembly|definedynamicmodule', param_lower):
        findings.append('STAGER:APPDOMAIN')

    # Runspace abuse (PowerShell-in-PowerShell)
    if (re.search(r'\[powershell\]::create\(\)|runspacefactory', param_lower)
            or in_order(param_lower, ['addscript', 'begininvoke'])):
        findings.append('STAGER:RUNSPACE')

    # Constrained Language Mode bypass
    if in_order(param_lower, ['languagemode', 'fulllanguage']) or 'fulllanguagemode' in param_lower:
        findings.append('STAGER:CLM_BYPASS')

    # Win32 API direct calls via Add-Type
    if (in_order(param_lower, ['add-type', 'dllimport', 'kernel32'])
            or in_order(param_lower, ['add-type', 'dllimport', 'ntdll'])):
        findings.append('STAGER:WIN32_API')

    return '|'.join(findings[:3]) if findings else ''
