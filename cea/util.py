import re
from dataclasses import asdict, dataclass

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f‪-‮⁦-⁩]")


def clean(s, limit=240):
    """Make untrusted text safe to print in a terminal / markdown report:
    strip control chars (ANSI escapes, bidi overrides), collapse whitespace,
    neutralise backticks, truncate."""
    if s is None:
        return ""
    if isinstance(s, bytes):
        s = s.decode("utf-8", "replace")
    s = _CTRL.sub("?", s).replace("\n", " ").replace("\r", " ").replace("`", "'")
    s = re.sub(r"\s{2,}", " ", s).strip()
    return s if len(s) <= limit else s[:limit] + "..."


@dataclass
class Finding:
    rule: str
    severity: str        # info | low | medium | high | critical
    title: str
    source: str          # static | dynamic
    file: str = ""
    line: int = 0
    evidence: str = ""
    context: str = ""    # install | import | run | runtime | dependency-install

    def to_dict(self):
        return asdict(self)
