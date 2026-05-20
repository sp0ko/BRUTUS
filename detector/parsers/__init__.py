from .linux_ssh import LinuxSSHParser
from .windows_evtx import WindowsEvtxParser

PARSER_REGISTRY = {
    "linux_ssh": LinuxSSHParser,
    "windows_evtx": WindowsEvtxParser,
}


def get_parser(parser_type: str):
    cls = PARSER_REGISTRY.get(parser_type)
    if cls is None:
        raise ValueError(
            f"Unknown parser type: '{parser_type}'. "
            f"Available: {list(PARSER_REGISTRY.keys())}"
        )
    return cls()
