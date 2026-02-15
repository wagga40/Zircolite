def transform(param):
    parts = param.replace('\\', '/').split('/')
    name = parts[-1] if parts else ''
    return name if name and name != param else ''
