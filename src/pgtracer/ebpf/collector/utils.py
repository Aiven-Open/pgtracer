"""
Various utilities for collector implementations.
"""
from enum import IntEnum
from pathlib import Path
from typing import Any, Dict, Type


def intenum_to_c(intenum: Type[IntEnum]) -> str:
    """
    Generate C code defining an enum corresponding to a Python IntEnum.
    """
    buf = f"enum {intenum.__name__} {{\n"
    members = []

    for member in intenum:
        members.append(f"{intenum.__name__}{member.name} = {member.value}")
    buf += ",\n".join(members)
    buf += "\n};\n"

    return buf


def defines_dict_to_c(defines_dict: Dict[str, Any]) -> str:
    """
    Generate a string of C #define directives from a mapping.
    """
    return (
        "\n".join(f"#define {key} {value}" for key, value in defines_dict.items())
        + "\n"
    )


CODE_BASE_PATH = Path(__file__).parent.parent / "code"


def load_c_file(filename: str) -> str:
    """
    Loads a C file from the package code directory.
    """
    filepath = CODE_BASE_PATH / filename
    with filepath.open() as cfile:
        return cfile.read()
