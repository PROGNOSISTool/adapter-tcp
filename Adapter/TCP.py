from enum import StrEnum
import json
import logging
from typing import Optional

class FlagSet:
    SYN: bool = False
    ACK: bool = False
    RST: bool = False
    FIN: bool = False
    PSH: bool = False
    URG: bool = False
    ECE: bool = False
    CWR: bool = False
    NS: bool = False

    def __init__(self, flags: str = "") -> None:
        self.setFlags(flags)
            

    def getFlags(self) -> list[str]:
        flags = []
        if self.SYN:
            flags.append('SYN')
        if self.ACK:
            flags.append('ACK')
        if self.RST:
            flags.append('RST')
        if self.FIN:
            flags.append('FIN')
        if self.PSH:
            flags.append('PSH')
        if self.URG:
            flags.append('URG')
        if self.ECE:
            flags.append('ECE')
        if self.CWR:
            flags.append('CWR')
        if self.NS:
            flags.append('NS')
        return flags
    
    def setFlags(self, flags: str):
        if 'S' in flags:
            self.SYN = True
        if 'A' in flags:
            self.ACK = True
        if 'R' in flags:
            self.RST = True
        if 'F' in flags:
            self.FIN = True
        if 'P' in flags:
            self.PSH = True
        if 'U' in flags:
            self.URG = True
        if 'E' in flags:
            self.ECE = True
        if 'C' in flags:
            self.CWR = True
        if 'N' in flags:
            self.NS = True

    def asScapy(self) -> str:
        return "".join(map(lambda f: f[0], self.getFlags()))
    
    def asHuman(self) -> str:
        return "+".join(self.getFlags())

    def toJSON(self) -> str:
        return json.dumps(self.getFlags())
