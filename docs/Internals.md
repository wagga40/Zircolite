# Internals

## Zircolite architecture

**Zircolite is more a workflow than a real detection engine**. To put it simply, it leverages the ability of the sigma converter to output rules in SQLite format. Zircolite simply applies SQLite-converted rules to EVTX stored in an in-memory SQLite DB.

![](pics/Zircolite.png)

## Project structure

```text
├── Makefile                # Very basic Makefile
├── Readme.md               # Do I need to explain ?
├── bin                     # Directory containing all external binaries (evtx_dump)
├── config                  # Directory containing the config files
├── docs                    # Directory containing the documentation
├── pics                    # Pictures directory - not really relevant
├── rules                   # Sample rules you can use
├── templates               # Jinja2 templates
├── tools                   # Directory containing all tools (genRules, zircolite_server)
└── zircolite.py            # Zircolite !
```
