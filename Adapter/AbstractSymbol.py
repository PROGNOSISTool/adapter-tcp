from enum import Enum, StrEnum, auto
from typing import List, Optional
import jsons
import re
from TCP import FlagSet


class Value(StrEnum):
    CURRENT = "CURRENT"
    NEXT = "NEXT"
    ZERO = "ZERO"
    FRESH = "FRESH"

validValues = list(map(lambda x: x.value, list(Value)))

class AbstractSymbol:
    flags: FlagSet = FlagSet()
    seqNumber: Optional[Value] | int = None
    ackNumber: Optional[Value] | int = None
    payloadLength: Optional[int] = None

    def __init__(self, symbol: str | tuple[str, Optional[Value] | int, Optional[Value] | int, int]):
        if isinstance(symbol, str):
            pattern = re.compile(r"([A-Z+]+)\(([A-Z0-9?]+),([A-Z0-9?]+),([0-9?]+)\)")
            capture = pattern.match(symbol)

            if capture is None:
                raise ValueError("Invalid abstract syntax:", symbol)

            self.flags = FlagSet("".join(map(lambda x: x[0], capture.group(1).split("+"))))
            if capture.group(2) in validValues:
                self.seqNumber = Value(capture.group(2))
            elif  capture.group(2).isdigit():
                self.seqNumber = int(capture.group(2))
            else:
                self.seqNumber = None

            if capture.group(3) in validValues:
                self.ackNumber = Value(capture.group(3))
            elif  capture.group(3).isdigit():
                self.ackNumber = int(capture.group(3))
            else:
                self.ackNumber = None

            self.payloadLength = int(capture.group(4)) if capture.group(4) != "?" else None

        else:
            self.flags = FlagSet(symbol[0])
            self.seqNumber = symbol[1]
            self.ackNumber = symbol[2]
            self.payloadLength = symbol[3]

    def __str__(self) -> str:
        flagsString = self.flags.asHuman()
        seqString = "?" if self.seqNumber is None else str(self.seqNumber)
        ackString = "?" if self.ackNumber is None else str(self.ackNumber)
        payloadLenString = "?" if self.payloadLength is None else str(self.payloadLength)
        return flagsString + "(" + seqString + "," + ackString + "," + payloadLenString + ")"

    def toJSON(self) -> str:
        return jsons.dumps(self)


class AbstractOrderedPair:
    abstractInputs: List[Optional[AbstractSymbol]] = []
    abstractOutputs: List[Optional[AbstractSymbol]] = []

    def __init__(self, inputs: List[Optional[AbstractSymbol]], outputs: List[Optional[AbstractSymbol]]):
        self.abstractInputs = inputs
        self.abstractOutputs = outputs

    def __str__(self) -> str:
        abstractInputStrings = map(str, self.abstractInputs)
        concreteInputStrings = map(str, self.abstractOutputs)

        aiString = "[{}]".format(", ".join(abstractInputStrings))
        aoString = "[{}]".format(", ".join(concreteInputStrings))
        return "({},{})".format(aiString, aoString)

    def toJSON(self) -> str:
        return jsons.dumps(self)
