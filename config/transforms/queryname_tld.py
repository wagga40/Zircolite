def transform(param):
    # Get top-level domain
    parts = param.rstrip('.').split('.')
    if len(parts) >= 2:
        return parts[-1]
    return ''
