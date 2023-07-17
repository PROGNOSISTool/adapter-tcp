from enum import Flag
from typing import List, Optional, Union
import jsons
import re

import scapy.layers.inet
from scapy.packet import Packet, Raw
import impacket.ImpactPacket

from TCP import FlagSet


class ConcreteSymbol:
    isNull: bool = True
    sourcePort: int = 20
    destinationPort: int = 80
    seqNumber: int = 0
    ackNumber: int = 0
    dataOffset: Optional[int] = None
    reserved: int = 0
    flags: FlagSet = FlagSet()
    window: int = 8192
    checksum: Optional[str] = None
    urgentPointer: int = 0
    payload: str = ""

    def __init__(self, packet: Optional[Union[impacket.ImpactPacket.TCP, scapy.layers.inet.TCP]] = None, string: Optional[str] = None):
        # Scapy object
        if packet is not None and isinstance(packet, scapy.layers.inet.TCP):
            self.isNull = False
            self.sourcePort = packet[scapy.layers.inet.TCP].sport
            self.destinationPort = packet[scapy.layers.inet.TCP].dport
            self.seqNumber = packet[scapy.layers.inet.TCP].seq
            self.ackNumber = packet[scapy.layers.inet.TCP].ack
            self.dataOffset = packet[scapy.layers.inet.TCP].dataofs
            self.reserved = packet[scapy.layers.inet.TCP].reserved
            
            self.flags = FlagSet(str(packet[scapy.layers.inet.TCP].flags))
            self.window = packet[scapy.layers.inet.TCP].window
            self.checksum = packet[scapy.layers.inet.TCP].chksum
            self.urgentPointer = packet[scapy.layers.inet.TCP].urgptr
            if Raw in packet:
                self.payload = packet[Raw].load.decode("utf-8")
        
        # Impacket object
        elif packet is not None and isinstance(packet, impacket.ImpactPacket.TCP):
            self.isNull = False
            self.sourcePort = packet.get_th_sport()
            self.destinationPort = packet.get_th_dport()
            self.seqNumber = packet.get_th_seq()
            self.ackNumber = packet.get_th_ack()
            self.dataOffset = packet.get_th_off()
            self.reserved = packet.get_th_reserved()

            self.flags.SYN = bool(packet.get_SYN())
            self.flags.RST = bool(packet.get_RST())
            self.flags.FIN = bool(packet.get_FIN())
            self.flags.PSH = bool(packet.get_PSH())
            self.flags.URG = bool(packet.get_URG())
            self.flags.ECE = bool(packet.get_ECE())
            self.flags.CWR = bool(packet.get_CWR())
            
            self.window = packet.get_th_win()
            self.checksum = packet.get_th_sum()
            self.urgentPointer = packet.get_th_urp()
            inData: Optional[str] = packet.get_data_as_string()
            if inData is not None:
                self.payload = inData.decode("utf-8")
            
        # Generic string object.
        elif string is not None:
            self.isNull = False
            pattern = re.compile(r"([A-Z+]+)\(([0-9]+),([0-9]+),([0-9]+)\)")
            capture = pattern.match(string)
            if capture is None:
                raise ValueError("Invalid concrete syntax:", string)
            
            inFlags = capture.group(1)
            if "+" in inFlags:
                inFlags = "".join(map(lambda x: x[0], inFlags.split("+")))
            self.flags = FlagSet(inFlags)
            
            self.seqNumber = int(capture.group(2))
            self.ackNumber = int(capture.group(3))
            self.payload = "A" * int(capture.group(4))

    def __str__(self) -> str:
        if self.isNull:
            return "NIL"
        else:
            flagsString = self.flags.asHuman()
            seqString = str(self.seqNumber)
            ackString = str(self.ackNumber)
            payloadLenString = str(len(self.payload))
            return (
                flagsString
                + "("
                + seqString
                + ","
                + ackString
                + ","
                + payloadLenString
                + ")"
            )

    def toJSON(self) -> str:
        if self.isNull:
            return "{}"
        else:
            return jsons.dumps(self)


class ConcreteOrderedPair:
    concreteInputs: List[ConcreteSymbol] = []
    concreteOutputs: List[ConcreteSymbol] = []

    def __init__(self, inputs: List[ConcreteSymbol], outputs: List[ConcreteSymbol]):
        self.concreteInputs = inputs
        self.concreteOutputs = outputs

    def toJSON(self) -> str:
        return jsons.dumps(self)
