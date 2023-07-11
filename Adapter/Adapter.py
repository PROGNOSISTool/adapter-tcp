from typing import List
import socket
import socketserver
import sys
import yaml
from scapy.all import *
from scapy.layers.inet import IP, TCP
from Mapper import Mapper
from AbstractSymbol import AbstractSymbol, AbstractOrderedPair
from ConcreteSymbol import ConcreteSymbol, ConcreteOrderedPair
from Tracker import Tracker
from OracleTable import OracleTable

import logging

logging.basicConfig(level=logging.DEBUG, format="%(name)s: %(message)s")


class Adapter:
    
    def __init__(self, impIp, impPort, timeout, interface, oracleTableURL):
        self.mapper =  Mapper(impPort)
        self.localAddr = socket.gethostbyname(socket.gethostname())
        self.impAddress = socket.gethostbyname(impIp)
        self.connection = IP(src=self.localAddr, dst=self.impAddress, flags="DF", version=4)
        self.oracleTable = OracleTable(oracleTableURL)
        self.timeout = timeout
        self.interface = interface
        self.tracker = Tracker(interface, self.impAddress)
        self.logger = logging.getLogger("Adapter")
        return

    def stop(self):
        self.tracker.stop()
        self.mapper.stop()

    def reset(self):
        self.logger.info("Sending RESET...")
        self.handleQuery("RST(?,?,?)")
        self.mapper.reset()
        self.logger.info("RESET finished.")

    def handleQuery(self, query: str) -> str:
        answers = []
        abstractSymbolsIn: List[AbstractSymbol] = []
        concreteSymbolsIn: List[AbstractSymbol] = []
        abstractSymbolsOut: List[ConcreteSymbol] = []
        concreteSymbolsOut: List[ConcreteSymbol] = []
        for symbol in query.split(" "):
            self.logger.info("Processing Symbol: " + symbol)

            abstractSymbolIn: AbstractSymbol = AbstractSymbol(string=symbol)
            self.logger.info("Abstract Symbol In: " + str(abstractSymbolIn))

            packetIn = self.mapper.abstractToConcrete(abstractSymbolIn)

            if packetIn is None:
                concreteSymbolIn: ConcreteSymbol = ConcreteSymbol()
                concreteSymbolOut: ConcreteSymbol = ConcreteSymbol()
                abstractSymbolOut: AbstractSymbol = AbstractSymbol()
            else:
                concreteSymbolIn: ConcreteSymbol = ConcreteSymbol(packet=packetIn)
                self.logger.info("Concrete Symbol In: " + concreteSymbolIn.toJSON())

                self.tracker.clearLastResponse()
                send([self.connection / packetIn], iface=self.interface, verbose=True)
                concreteSymbolOut: ConcreteSymbol = self.tracker.sniffForResponse(
                    packetIn[TCP].dport, packetIn[TCP].sport, self.timeout
                )
                self.logger.info("Concrete Symbol Out: " + concreteSymbolOut.toJSON())

                if not concreteSymbolOut.isNull:
                    abstractSymbolOut: AbstractSymbol = self.mapper.concreteToAbstract(
                        concreteSymbolOut
                    )
                    # Match abstraction level.
                    if abstractSymbolIn.seqNumber is None:
                        abstractSymbolOut.seqNumber = None
                    if abstractSymbolIn.ackNumber is None:
                        abstractSymbolOut.ackNumber = None
                    if abstractSymbolIn.payloadLength is None:
                        abstractSymbolOut.payloadLength = None
                else:
                    concreteSymbolOut.isNull = True
                    abstractSymbolOut: AbstractSymbol = AbstractSymbol()
                    abstractSymbolOut.isNull = True

                self.logger.info("Abstract Symbol Out: " + str(abstractSymbolOut))

            answers.append(str(abstractSymbolOut))

            abstractSymbolsIn.append(abstractSymbolIn)
            concreteSymbolsIn.append(concreteSymbolIn)
            abstractSymbolsOut.append(abstractSymbolOut)
            concreteSymbolsOut.append(concreteSymbolOut)

        self.oracleTable.add(
            AbstractOrderedPair(abstractSymbolsIn, abstractSymbolsOut),
            ConcreteOrderedPair(concreteSymbolsIn, concreteSymbolsOut),
        )
        return " ".join(answers)


class QueryRequestHandler(socketserver.StreamRequestHandler):
    def __init__(self, request, client_address, server):
        self.logger = logging.getLogger("Query Handler")
        socketserver.BaseRequestHandler.__init__(self, request, client_address, server)
        return

    def handle(self):
        while True:
            query = self.rfile.readline().strip().decode("utf-8").rstrip("\n")
            if query != "":
                self.logger.info("Received query: " + query)
                if query == "STOP":
                    self.server.adapter.stop()
                    self.wfile.write(bytearray("STOP" + "\n", "utf-8"))
                    break
                elif query == "RESET":
                    self.server.adapter.reset()
                    self.wfile.write(bytearray("RESET" + "\n", "utf-8"))
                else:
                    answer = self.server.adapter.handleQuery(query)
                    self.logger.info("Sending answer: " + answer)
                    self.wfile.write(bytearray(answer + "\n", "utf-8"))
            else:
                self.wfile.write(bytearray("NIL\n", "utf-8"))
        sys.exit(0)


class AdapterServer(socketserver.TCPServer):
            
    def __init__(self, config, handler_class=QueryRequestHandler):
        self.adapter = Adapter(str(config["impAddress"]), config["impPort"], config["timeout"], config["interface"], config["oracleTableURL"])
        self.adapter.tracker.start()
        self.logger = logging.getLogger("Server")
        self.logger.info("Initialising server...")
        socketserver.TCPServer.__init__(self, ("0.0.0.0", config["port"]), handler_class)
        return

def loadConfig(path):
    with open(path, "r") as stream:
        return yaml.safe_load(stream)["adapter"]

config = loadConfig("/root/config.yaml")
server = AdapterServer(config, QueryRequestHandler)

if __name__ == "__main__":
    server.serve_forever()
