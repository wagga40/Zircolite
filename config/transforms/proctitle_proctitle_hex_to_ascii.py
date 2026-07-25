def transform(param):
    # auditd only hex-encodes the field when it contains spaces or quotes, so
    # plain text arrives here too and must pass through untouched rather than
    # relying on the caller to swallow a ValueError.
    try:
        decoded = bytes.fromhex(param)
    except ValueError:
        return param
    try:
        return decoded.decode('ascii').replace('\x00', ' ')
    except UnicodeDecodeError:
        return param
