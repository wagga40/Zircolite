def transform(param):
    import re
    indicators = []
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
        # Most text lacks the first step, or any later one after it: one
        # search each settles that before the ordered scan is paid for.
        head = re.search(patterns[0], text, flags)
        if head is None:
            return False
        compiled = [re.compile(p, flags) for p in patterns]
        for step in compiled[1:]:
            if step.search(text, head.start()) is None:
                return False
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

    # VirtualAlloc with executable permissions
    # One case-insensitive search rules out most scripts; 'i' also matches
    # dotless and dotted I under IGNORECASE, so a lowercase test would not.
    if (re.search('virtualalloc', param, re.IGNORECASE)
            and (in_order(param, ['virtualalloc', '0x40'], re.IGNORECASE)
                 or in_order(param, ['virtualalloc', 'page_execute'], re.IGNORECASE))):
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
