def transform(param):
    logon_types = {
        '0': 'SYSTEM',
        '2': 'INTERACTIVE',
        '3': 'NETWORK',
        '4': 'BATCH',
        '5': 'SERVICE',
        '7': 'UNLOCK',
        '8': 'NETWORK_CLEARTEXT',
        '9': 'NEW_CREDENTIALS',
        '10': 'REMOTE_INTERACTIVE',
        '11': 'CACHED_INTERACTIVE',
        '12': 'CACHED_REMOTE_INTERACTIVE',
        '13': 'CACHED_UNLOCK',
    }
    val = str(param).strip()
    return logon_types.get(val, 'UNKNOWN:' + val)
