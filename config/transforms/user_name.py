def transform(param):
    # Handle DOMAIN\user or user@domain formats
    if '\\' in param:
        return param.split('\\')[-1]
    elif '@' in param:
        return param.split('@')[0]
    return ''
