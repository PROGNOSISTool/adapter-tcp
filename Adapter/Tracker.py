# From: https://gitlab.science.ru.nl/pfiteraubrostean/tcp-learner/-/blob/master/Adapter/tracker.py

from typing import Optional
from pcapy import open_live
from impacket.ImpactDecoder import EthDecoder, Dot11WPA2Decoder, Decoder
from impacket.ImpactPacket import IP, TCP
import time
import threading
from ConcreteSymbol import ConcreteSymbol


class Tracker(threading.Thread):
    serverPort = 0
    senderPort = 0
    pcap = None
    max_bytes = 1024
    promiscuous = False

    def __init__(self, interface: str, serverIp, interfaceType: int = 0, readTimeout: int = 1):
        super(Tracker, self).__init__()
        self.interface = interface
        self.decoder = self.getDecoder(interfaceType)
        self._stop = threading.Event()
        self._received = threading.Event()
        self.daemon = True
        self.readTimeout = readTimeout
        self.serverIp = serverIp
        self.lastResponse: Optional[ConcreteSymbol] = None
        self.lastResponses: dict[tuple[int, int], ConcreteSymbol] = dict()
        self.responseHistory: set[tuple[tuple[int, int], int, int, str]] = set()

    def getDecoder(self, interfaceType) -> EthDecoder | Dot11WPA2Decoder:
        if interfaceType == 0:
            return EthDecoder()
        else:
            return Dot11WPA2Decoder()

    def stop(self) -> None:
        self._stop.set()

    def isStopped(self) -> bool:
        return self._stop.isSet()

    # This is method is called periodically by pcapy
    def callback(self, hdr, data):
        if self.isStopped() == True:
            print("Tracker is stopped.")
            exit(-1)  # results in a strange warning
        else:
            if data is None:
                return
            packet = self.decoder.decode(data)
            if packet is None:
                return

            l2 = packet.child()
            if isinstance(l2, IP):
                l3 = l2.child()
                if isinstance(l3, TCP):
                    tcp_src_port = l3.get_th_sport()
                    tcp_dst_port = l3.get_th_dport()
                    response = self.impacketResponseParse(l3)
                    print("PACKET:", response)
                    print("HIST:", self.responseHistory)
                    if self.isRetransmit(tcp_src_port, tcp_dst_port, response):
                        print("ignoring retransmission: ", response.__str__())
                    else:
                        self.responseHistory.add(
                            (
                                (tcp_src_port, tcp_dst_port),
                                response.seqNumber,
                                response.ackNumber,
                                response.flags.asScapy(),
                            )
                        )
                        self.lastResponses[(tcp_src_port, tcp_dst_port)] = response
                        self.lastResponse = response
                        self._received.set()

    def isRetransmit(self, tcp_src_port: int, tcp_dst_port: int, response: ConcreteSymbol) -> bool:
        isRet = (
            (tcp_src_port, tcp_dst_port),
            response.seqNumber,
            response.ackNumber,
            response.flags.asScapy(),
        ) in self.responseHistory and response.flags.asScapy().replace("U", "") in [
            "SA",
            "AS",
            "AF",
            "FA",
            "S",
            "P",
            "PA",
        ]

        # Technically, seq numbers don't identify packets but data.
        # So we could get a packet with a previously seen SEQ number, except that now it actualy carries data.
        if not isRet:
            if response.flags.PSH and response.flags.ACK and len(response.payload) > 0:
                for (src_port, dst_port), seq, ack, flags in self.responseHistory:
                    if (src_port, dst_port) == (tcp_src_port, tcp_dst_port) and (seq == response.seqNumber) and "P" in flags and "A" in flags:
                        isRet = True
        return isRet

    def impacketResponseParse(self, tcpPacket: TCP):
        return ConcreteSymbol(tcpPacket)

    # clears all last responses for all ports (keep that in mind if you have responses on several ports)
    # this is done because when learning, we only care about one port
    def clearLastResponse(self) -> None:
        self.lastResponse = None
        self.lastResponses.clear()

    def reset(self) -> None:
        self.clearLastResponse()
        self.responseHistory.clear()
        self._received.clear()

    def sniffForResponse(self, serverPort: int, senderPort: int, waitTime) -> Optional[ConcreteSymbol]:
        div = waitTime / 10
        response = None
        # print "sniffing for response ", waitTime
        for _ in range(10):
            # print "waiting... ", div
            time.sleep(div)
            response = self.getLastResponse(serverPort, senderPort)
            if response is not None:
                break
                # self._received.wait(timeout=waitTime)
        # response = self.getLastResponse(serverPort, senderPort)
        # self._received.clear()
        return response

    # fetches the last response from an active port. If no response was sent, then it returns a null symbol.
    def getLastResponse(self, serverPort: int, senderPort: int) -> Optional[ConcreteSymbol]:
        hist = self.lastResponses.get((serverPort, senderPort))
        if hist is not None:
            return hist

    def run(self) -> None:
        self.trackPackets()

    def trackPackets(self) -> None:
        self.pcap = open_live(self.interface, self.max_bytes, self.promiscuous, self.readTimeout)
        self.pcap.setfilter("tcp and ip src " + str(self.serverIp))
        while True:
            (header, packet) = self.pcap.next()
            self.callback(header, packet)
