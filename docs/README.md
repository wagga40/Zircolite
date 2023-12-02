# Zircolite documentation

**Zircolite is a standalone tool written in Python 3. It allows to use SIGMA rules on : MS Windows EVTX (EVTX, XML and JSONL format), Auditd logs, Sysmon for Linux and EVTXtract logs**

- **Zircolite** can be used directly on the investigated endpoint or in your forensic/detection lab
- **Zircolite** is relatively fast and can parse large datasets in just seconds 
- **Zircolite** is based on a Sigma backend (SQLite) and do not use internal sigma to "something" conversion
- **Zircolite** can export results to multiple format with using Jinja : JSON, CSV, JSONL, Splunk, Elastic, Zinc, Timesketch...

**Zircolite can be used directly in Python or you can use the binaries provided in [releases](https://github.com/wagga40/Zircolite/releases).** 
