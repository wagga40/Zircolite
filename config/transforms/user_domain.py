def transform(param):
    # Handle DOMAIN\user or user@domain formats
    if '\\' in param:
        parts = param.split('\\')
        return parts[0] if len(parts) > 1 else ''
    elif '@' in param:
        parts = param.split('@')
        return parts[1] if len(parts) > 1 else ''
    return ''
