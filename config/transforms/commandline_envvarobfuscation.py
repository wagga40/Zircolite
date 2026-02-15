def transform(param):
    import re
    indicators = []
    
    # Environment variable character-by-character extraction
    # e.g., %comspec:~0,1% extracts first char of COMSPEC
    if re.search(r'%[^%]+:~\d+,\d+%', param):
        indicators.append('ENV_CHAR_EXTRACT')
    
    # Multiple env var substitutions (obfuscation indicator)
    env_count = len(re.findall(r'%[a-zA-Z_]+%', param))
    if env_count > 3:
        indicators.append('MULTI_ENV_VAR:' + str(env_count))
    
    # Suspicious env vars
    suspicious_vars = ['comspec', 'pathext', 'temp', 'tmp', 'appdata', 'programdata']
    for var in suspicious_vars:
        if re.search(r'%' + var + r'%', param, re.IGNORECASE):
            indicators.append('ENV:' + var.upper())
    
    return '|'.join(indicators) if indicators else ''
