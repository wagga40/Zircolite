# genRules
[![python](https://img.shields.io/badge/python-3.8-blue)](https://www.python.org/)
![version](https://img.shields.io/badge/Platform-Win-green)
![version](https://img.shields.io/badge/Platform-Lin-green)
![version](https://img.shields.io/badge/Platform-Mac-green)
![version](https://img.shields.io/badge/Architecture-64bit-red)

**`genRules.py` allows to convert SIGMA rules to Zircolite ruleset**. 

## Requirements 

### Libs

GenRules use the following third party Python libraries : **PyYAML**. You can install it with : `pip3 install -r requirements.txt`.

### Tools

GenRules needs `sigmac` from the SIGMA repository (not from PIP). The easiest way is to clone the SIGMA repository : 

`git clone https://github.com/SigmaHQ/sigma.git`  

## Quickstart

```shell
python3 genRules.py --rulesdirectory=<rules directory> \ 
						  --config=<sigmac config> --sigmac=<sigmac location>
python3 genRules.py --rulesdirectory=../../sigma/rules/windows/ \ 
						  --config=config/sysmon.yml --sigmac=../../sigma/tools/sigmac
```

The configuration file provided (`--config`) is the sigmac config file, the are some **very basic** samples in the `config` directory (Mostly copied from the SIGMA repository). Currently, only one configuration file is supported.

