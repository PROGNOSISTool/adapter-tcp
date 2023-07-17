import shlex
import subprocess
import string
import random
from typing import Optional

from scapy.layers.inet import TCP
from scapy.packet import Packet, Raw

from AbstractSymbol import AbstractSymbol
from ConcreteSymbol import ConcreteSymbol

import logging

logging.basicConfig(level=logging.DEBUG, format="%(name)s: %(message)s")


class Mapper:
    def __init__(self, impPort):
        self.destinationPort = impPort
        self.sourcePort: int = random.randint(1024, 65535)
        self.logger = logging.getLogger("Mapper")
        self.process: subprocess.Popen = subprocess.Popen(
            shlex.split(
                'java -cp "/code/Mapper/dist/TCPMapper.jar:/code/Mapper/lib/*" Mapper'
            ),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )

    def writeAndRead(self, input: str) -> str:
        if self.process.stdin is not None and self.process.stdout is not None:
            self.process.stdin.write(bytearray(input + "\n", "utf-8"))
            self.process.stdin.flush()
            return self.process.stdout.readline().decode("utf-8").rstrip("\n")
        raise ValueError("Could not reach mapper process pipes.")

    def abstractToConcrete(self, symbol: AbstractSymbol) -> Optional[Packet]:
        out = self.writeAndRead("ABSTRACT " + str(symbol))
        self.logger.debug("GOT: " + out)

        abs = AbstractSymbol(string=out)

        if abs.seqNumber is None or abs.ackNumber is None:
            return None

        payload = None
        if abs.payloadLength is not None and abs.payloadLength != 0:
            payload = self.randomPayload(abs.payloadLength)

        packet = TCP(
            flags=abs.flags.asScapy(),
            sport=self.sourcePort,
            dport=self.destinationPort,
            seq=abs.seqNumber,
            ack=abs.ackNumber,
        )

        if payload is not None:
            packet = packet / Raw(load=payload)

        return packet

    def concreteToAbstract(self, symbol: ConcreteSymbol) -> AbstractSymbol:
        self.writeAndRead("CONCRETE " + str(symbol))
        abs = AbstractSymbol(
            flags=symbol.flags.asScapy(),
            seqNumber=symbol.seqNumber,
            ackNumber=symbol.ackNumber,
            payloadLength=len(symbol.payload),
        )
        return abs

    def randomPayload(self, size: int) -> str:
        payload = ""
        for _ in range(size):
            payload += random.choice(string.ascii_letters)
        return payload

    def reset(self):
        self.sourcePort = random.randint(1024, 65535)
        self.writeAndRead("RESET")

    def stop(self) -> None:
        self.process.kill()
