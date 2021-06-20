# Zircolite documentation

## Internals

* [Zircolite architecture](#zircolite-architecture)
* [Project structure](#project-structure)
* [Benchmarks](#benchmarks)

---

### Zircolite architecture

**Zircolite is more a workflow than a real detection engine**. To put it simply, it leverages the ability of the sigma converter to output rules in SQLite format. Zircolite simply applies SQLite-converted rules to EVTX stored in an in-memory SQLite DB.

![](../pics/Zircolite.png)

---

### Project structure

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

---

### Benchmarks (**Updated 22nd May 2021**)

On an Intel Core-i9 8c/16t - 64 GB RAM - with **765 sigma rules** :

|                                                    | Monocore | Multicore  |
|----------------------------------------------------|----------|------------|
| EVTX : 34 GB - 16 files                            | -        | 9 Min      |
| EVTX : 7.8 GB - 4 files                            | -        | 162 sec    |
| EVTX : 1.7 GB - 1 file                             | 99 sec   | -          |
| EVTX : 40 MB  - 263 files                          | 3 sec    | 1 sec      |
| MORDOR Datasets - APT29 Day 1 (196 081 events)     | 62 sec   | -          |
| MORDOR Datasets - APT29 Day 2 (587 286 events)     | 4 min    | -          |
| MORDOR Datasets - APT3 Scenario 1 (101 904 events) | 70 sec   | -          |
| MORDOR Datasets - APT3 Scenario 2 (121 659 events) | 27 sec   | -          |

:information_source: These results can be largely improved with fine-tuned rulesets and filtering.
