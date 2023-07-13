from enum import StrEnum
import json
import logging
from typing import Optional


class Flag(StrEnum):
    SYN = "S"
    ACK = "A"
    RST = "R"
    FIN = "F"
    PSH = "P"
    URG = "U"
    ECE = "E"
    CWR = "C"
    NS = "N"
    UNKNOWN = "?"

    def toChar(self) -> str:
        return self.value

    def __str__(self) -> str:
        return self.name


class FlagSet(set):
    def __init__(self, flags: Optional[str] = None) -> None:
        super().__init__()
        if flags is not None:
            for char in flags:
                self.add(Flag(char))

    def asScapy(self) -> str:
        string = ""
        for flag in self:
            string = string + flag.toChar()
        return string

    def __str__(self) -> str:
        flags = []
        for flag in self:
            flags.append(str(flag))
        return "+".join(sorted(flags))

    def toJSON(self) -> str:
        flags = []
        for flag in self:
            flags.append(str(flag))
        return json.dumps(sorted(flags))
