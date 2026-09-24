def transform(param):
    import re
    # Each extractor returns what re.findall(pattern, param)[0] held for the
    # pattern in its comment, but in linear time. The patterns have up to
    # two greedy '.+' around credential tokens; on a long command line with
    # the tool name, the user flag and no password flag, the regex engine
    # backtracks through every combination, which is cubic in the length.
    #
    # The shared facts the rewrite rests on:
    # - '.' stops at newlines, and if a match starts at some occurrence of
    #   the tool name, one also starts at the first occurrence on that line
    #   (its '.+' just grows). findall reports the leftmost, so per line
    #   only the first occurrence needs trying.
    # - Greedy '.+' picks the rightmost place the rest can match.
    # - A token can only start after the whole whitespace run, since
    #   neither token form can start with whitespace, and a quoted token
    #   has exactly one possible end (the first unescaped quote).
    quoted_re = re.compile(r'"((?:\\.|[^"\\])*)"')
    bare_re = re.compile(r'[^\s"]+')
    newline_ends = [m.start() for m in re.finditer('\n', param)]
    newline_ends.append(len(param))

    def line_end(pos):
        # Index of the first newline at or after pos (len(param) if none).
        low = 0
        high = len(newline_ends) - 1
        while low < high:
            mid = (low + high) // 2
            if newline_ends[mid] < pos:
                low = mid + 1
            else:
                high = mid
        return newline_ends[low]

    def token(pos):
        # The groups a (?:"((?:\\.|[^"\\])*)")|(?:[^\s"]+) token starting
        # at pos captures, as [whole, quoted inner], or None.
        m = quoted_re.match(param, pos)
        if m is not None:
            return [m.group(0), m.group(1)]
        m = bare_re.match(param, pos)
        if m is not None:
            return [m.group(0), '']
        return None

    def tool_starts(tool):
        # The first occurrence of tool on each line.
        starts = []
        pos = param.find(tool)
        while pos != -1:
            starts.append(pos)
            end = line_end(pos)
            if end >= len(param):
                break
            pos = param.find(tool, end + 1)
        return starts

    def extract_net(tool, pattern):
        # 'net.+user\s+U\s+P' and 'net.+use\s+SHARE\s+/USER:U\s+P' have
        # no second '.+', so from a single start the engine only walks back
        # over the line once; it is the retry from every 'net' that costs.
        compiled = re.compile(pattern)
        for start in tool_starts(tool):
            m = compiled.match(param, start)
            if m is not None:
                return list(m.groups())
        return None

    def extract_split(tool, user_flag, password_flag):
        # tool.+USER_FLAG(U).+PASSWORD_FLAG(P)
        user_flag_re = re.compile(user_flag)
        password_flag_re = re.compile(password_flag)
        user_flag_literal = re.compile(re.escape(user_flag.split('\\')[0]))
        password_flag_literal = re.compile(re.escape(password_flag.split('\\')[0]))

        # Where a password flag followed by a password token starts, keyed
        # by the end of its line: only the last one on each line matters,
        # because the second '.+' is greedy and cannot leave the line.
        last_password = {}
        for flag in password_flag_literal.finditer(param):
            full = password_flag_re.match(param, flag.start())
            if full is not None and token(full.end()) is not None:
                last_password[line_end(flag.start())] = flag.start()

        for start in tool_starts(tool):
            first_end = start + len(tool)
            end = line_end(first_end)
            # The first '.+' needs at least one character, on this line.
            user_flags = [m.start() for m in user_flag_literal.finditer(param, first_end + 1, end)]
            index = len(user_flags) - 1
            while index >= 0:
                flag = user_flag_re.match(param, user_flags[index])
                index -= 1
                if flag is None:
                    continue
                token_start = flag.end()
                if token_start >= len(param):
                    continue
                if param[token_start] == '"':
                    quoted = quoted_re.match(param, token_start)
                    if quoted is None:
                        continue
                    user = [quoted.group(0), quoted.group(1)]
                    user_end = quoted.end()
                else:
                    bare = bare_re.match(param, token_start)
                    if bare is None:
                        continue
                    # Greedy: the longest username that still leaves one
                    # character for '.+' before the last password flag.
                    user_end = bare.end()
                    password_at = last_password.get(line_end(token_start), -1)
                    if password_at - 1 < user_end:
                        user_end = password_at - 1
                    if user_end < token_start + 1:
                        continue
                    user = [param[token_start:user_end], '']
                password_at = last_password.get(line_end(user_end), -1)
                if password_at < user_end + 1:
                    continue
                password = token(password_flag_re.match(param, password_at).end())
                return user + password
        return None

    extractors = [
        # r'net.+user\s+(?P<username>...)\s+(?P<password>...)'
        lambda: extract_net('net', r'net.+user\s+(?P<username>(?:"((?:\\.|[^"\\])*)")|(?:[^\s"]+))\s+(?P<password>(?:"((?:\\.|[^"\\])*)")|(?:[^\s"]+))'),
        # r'net.+use\s+(?P<share>\\\\\S+)\s+/USER:(?P<username>...)\s+(?P<password>...)'
        lambda: extract_net('net', r'net.+use\s+(?P<share>\\\\\S+)\s+/USER:(?P<username>(?:"((?:\\.|[^"\\])*)")|(?:[^\s"]+))\s+(?P<password>(?:"((?:\\.|[^"\\])*)")|(?:[^\s"]+))'),
        # r'schtasks.+/U\s+(?P<username>...).+/P\s+(?P<password>...)'
        lambda: extract_split('schtasks', r'/U\s+', r'/P\s+'),
        # r'wmic.+/user:\s*(?P<username>...).+/password:\s*(?P<password>...)'
        lambda: extract_split('wmic', r'/user:\s*', r'/password:\s*'),
        # r'psexec.+-u\s+(?P<username>...).+-p\s+(?P<password>...)'
        lambda: extract_split('psexec', r'-u\s+', r'-p\s+'),
    ]
    matches = []
    for extract in extractors:
        found = extract()
        if found is not None:
            for match in found:
                if match is not None and len(match) > 0:
                    matches.append(match)
    concatenated_result = '|'.join(matches)
    if concatenated_result == None:
        return ''
    return concatenated_result
