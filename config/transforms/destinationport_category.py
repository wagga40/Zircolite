def transform(param):
    try:
        port = int(param)
    except (ValueError, TypeError):
        return ''
    
    # Well-known categories
    if port == 80:
        return 'HTTP'
    elif port == 443:
        return 'HTTPS'
    elif port == 445:
        return 'SMB'
    elif port == 3389:
        return 'RDP'
    elif port == 22:
        return 'SSH'
    elif port == 21:
        return 'FTP'
    elif port == 20:
        return 'FTP_DATA'
    elif port == 23:
        return 'TELNET'
    elif port == 53:
        return 'DNS'
    elif port == 25 or port == 587 or port == 465:
        return 'SMTP'
    elif port in [135, 139]:
        return 'RPC_NETBIOS'
    elif port == 137:
        return 'NETBIOS_NS'
    elif port == 138:
        return 'NETBIOS_DGM'
    elif port == 1433:
        return 'MSSQL'
    elif port == 3306:
        return 'MYSQL'
    elif port == 5432:
        return 'POSTGRESQL'
    elif port == 1521:
        return 'ORACLE'
    elif port == 27017:
        return 'MONGODB'
    elif port == 6379:
        return 'REDIS'
    elif port == 5985 or port == 5986:
        return 'WINRM'
    elif port == 88:
        return 'KERBEROS'
    elif port == 389:
        return 'LDAP'
    elif port == 636:
        return 'LDAPS'
    elif port == 3268:
        return 'LDAP_GC'
    elif port == 3269:
        return 'LDAPS_GC'
    elif port == 464:
        return 'KERBEROS_PASSWD'
    elif port == 4444:
        return 'METASPLOIT_DEFAULT'
    elif port == 4445:
        return 'METASPLOIT_ALT'
    elif port == 8080 or port == 8443:
        return 'ALT_HTTP'
    elif port == 8000 or port == 8888:
        return 'DEV_HTTP'
    elif port == 9090:
        return 'OPENFIRE'
    elif port == 110:
        return 'POP3'
    elif port == 995:
        return 'POP3S'
    elif port == 143:
        return 'IMAP'
    elif port == 993:
        return 'IMAPS'
    elif port == 161:
        return 'SNMP'
    elif port == 162:
        return 'SNMP_TRAP'
    elif port == 69:
        return 'TFTP'
    elif port == 514:
        return 'SYSLOG'
    elif port == 515:
        return 'LPD'
    elif port == 548:
        return 'AFP'
    elif port == 873:
        return 'RSYNC'
    elif port == 1080:
        return 'SOCKS'
    elif port == 1194:
        return 'OPENVPN'
    elif port == 1723:
        return 'PPTP'
    elif port == 2049:
        return 'NFS'
    elif port == 2375 or port == 2376:
        return 'DOCKER'
    elif port == 5000:
        return 'DOCKER_REGISTRY'
    elif port == 5900:
        return 'VNC'
    elif port == 6000:
        return 'X11'
    elif port == 8081:
        return 'PROXY'
    elif port == 9200:
        return 'ELASTICSEARCH'
    elif port == 9300:
        return 'ELASTICSEARCH_CLUSTER'
    elif port == 11211:
        return 'MEMCACHED'
    elif port == 50000:
        return 'SAP'
    elif port >= 49152:
        return 'EPHEMERAL'
    elif port >= 1024:
        return 'HIGH_PORT'
    else:
        return 'WELL_KNOWN'
