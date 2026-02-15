def transform(param):
    # Extract filename from path (works for both / and \)
    parts = param.replace('\\', '/').split('/')
    name = parts[-1] if parts else ''
    # Only return if we actually extracted something different from the full path
    return name if name and name != param else ''
