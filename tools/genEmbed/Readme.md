# genEmbed
[![python](https://img.shields.io/badge/python-3.8-blue)](https://www.python.org/)

**`genEmbed.py` use Jinja templating system to generate Zircolite embedded versions**. 

## Requirements 

GenEmbed use the following third party Python libraries : **Jinja2**. You can install it with : `pip3 install -r requirements.txt`.

## Quickstart

If you are at the root of the Zircolite repository : 

```shell 
python3 tools/genEmbed/genEmbed.py -z zircolite.py \
			-c config/fieldMappings.json -m embedded -e bin/evtx_dump_lin \
			-r rules/ -t templates/ -o zircolite_embedded_lin.py 
```

It will create a `zircolite_embedded_lin.py` that will be an embedded version of Zircolite (with rules, external tools and config files).

If you use the `--mode standard` option, it is possible to generate a cleaner Zircolite.py file (without Jinja markup).