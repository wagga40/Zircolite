def transform(param):
    import re
    indicators = []
    param_lower = param.lower()
    
    # PowerShell download cradles
    if 'downloadstring' in param_lower:
        indicators.append('DOWNLOADSTRING')
    if 'downloadfile' in param_lower:
        indicators.append('DOWNLOADFILE')
    if 'downloaddata' in param_lower:
        indicators.append('DOWNLOADDATA')
    if 'invoke-webrequest' in param_lower or 'iwr' in param_lower:
        indicators.append('INVOKE_WEBREQUEST')
    if 'invoke-restmethod' in param_lower or 'irm' in param_lower:
        indicators.append('INVOKE_RESTMETHOD')
    if 'webclient' in param_lower:
        indicators.append('WEBCLIENT')
    if 'bitstransfer' in param_lower:
        indicators.append('BITSTRANSFER')
    
    # Certutil download
    if re.search(r'certutil.*-urlcache', param, re.IGNORECASE):
        indicators.append('CERTUTIL_DOWNLOAD')
    
    # Bitsadmin download
    if re.search(r'bitsadmin.*/transfer', param, re.IGNORECASE):
        indicators.append('BITSADMIN_DOWNLOAD')
    
    # Curl/wget
    if re.search(r'\b(curl|wget)\b', param, re.IGNORECASE):
        indicators.append('CURL_WGET')
    
    return '|'.join(indicators) if indicators else ''
