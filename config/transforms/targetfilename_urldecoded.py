def transform(param):
    import re
    if '%' not in param:
        return ''
    def decode_match(m):
        return chr(int(m.group(1), 16))
    decoded = re.sub(r'%([0-9A-Fa-f]{2})', decode_match, param)
    return decoded if decoded != param else ''
