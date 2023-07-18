from typing import List, Optional
import jsons
import re
from TCP import FlagSet


class AbstractSymbol:
    flags: FlagSet = FlagSet()
    seqNumber: Optional[int] = None
    ackNumber: Optional[int] = None
    payloadLength: Optional[int] = None

    def __init__(self, symbol: str | tuple[str, int, int, int]):
        if isinstance(symbol, str):
            pattern = re.compile(r"([A-Z+]+)\(([0-9?]+),([0-9?]+),([0-9?]+)\)")
            capture = pattern.match(symbol)

            if capture is None:
                raise ValueError("Invalid abstract syntax:", symbol)

            self.flags = FlagSet("".join(map(lambda x: x[0], capture.group(1).split("+"))))
            self.seqNumber = int(capture.group(2)) if capture.group(2) != "?" else None
            self.ackNumber = int(capture.group(3)) if capture.group(3) != "?" else None
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
