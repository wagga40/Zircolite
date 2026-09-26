def transform(param):
    import re
    regex_patterns = [
        r'net.+user\s+(?P<username>(?:"((?:\\.|[^"\\])*)")|(?:[^\s"]+))\s+(?P<password>(?:"((?:\\.|[^"\\])*)")|(?:[^\s"]+))',
        r'net.+use\s+(?P<share>\\\\\S+)\s+/USER:(?P<username>(?:"((?:\\.|[^"\\])*)")|(?:[^\s"]+))\s+(?P<password>(?:"((?:\\.|[^"\\])*)")|(?:[^\s"]+))',
        r'schtasks.+/U\s+(?P<username>(?:"((?:\\.|[^"\\])*)")|(?:[^\s"]+)).+/P\s+(?P<password>(?:"((?:\\.|[^"\\])*)")|(?:[^\s"]+))',
        r'wmic.+/user:\s*(?P<username>(?:"((?:\\.|[^"\\])*)")|(?:[^\s"]+)).+/password:\s*(?P<password>(?:"((?:\\.|[^"\\])*)")|(?:[^\s"]+))',
        r'psexec.+-u\s+(?P<username>(?:"((?:\\.|[^"\\])*)")|(?:[^\s"]+)).+-p\s+(?P<password>(?:"((?:\\.|[^"\\])*)")|(?:[^\s"]+))'
    ]
    matches = []
    for pattern in regex_patterns:
        found = re.findall(pattern, param)
        if len(found) > 0:
            for match in list(found[0]):
                if len(match) > 0:
                    matches.append(match)
    concatenated_result = '|'.join(matches)
    if concatenated_result == None:
        return ''
    return concatenated_result
