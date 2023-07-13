import socket
import socketserver
import sys
import yaml
from scapy.all import send
from scapy.layers.inet import IP, TCP

from AbstractSymbol import AbstractSymbol, AbstractOrderedPair
from Mapper import Mapper
from ConcreteSymbol import ConcreteSymbol, ConcreteOrderedPair
from Tracker import Tracker
from OracleTable import OracleTable

import logging

logging.basicConfig(level=logging.DEBUG, format="%(name)s: %(message)s")


class Adapter:
    def __init__(
        self,
        impIp: str,
        impPort: int,
        timeout: float,
        interface: str,
        oracleTableURL: str,
    ):
        self.mapper = Mapper(impPort)
        self.localAddr: str = socket.gethostbyname(socket.gethostname())
        self.impAddress: str = socket.gethostbyname(impIp)
        self.connection: IP = IP(
            src=self.localAddr, dst=self.impAddress, flags="DF", version=4
        )
        self.oracleTable: OracleTable = OracleTable(oracleTableURL)
        self.timeout: float = timeout
        self.interface: str = interface
        self.tracker: Tracker = Tracker(interface, self.impAddress)
        self.logger: logging.Logger = logging.getLogger("Adapter")
        return

    def stop(self) -> None:
        self.tracker.stop()
        self.mapper.stop()

    def reset(self) -> None:
        self.logger.info("Sending RESET...")
        self.handleQuery("RST(?,?,?)")
        self.mapper.reset()
        self.logger.info("RESET finished.")

    def handleQuery(self, query: str) -> str:
        answers = []
        abstractSymbolsIn: list[AbstractSymbol] = []
        concreteSymbolsIn: list[ConcreteSymbol] = []
        abstractSymbolsOut: list[AbstractSymbol] = []
        concreteSymbolsOut: list[ConcreteSymbol] = []
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
                    if isinstance(self.server, AdapterServer):
                        self.server.adapter.stop()
                        self.wfile.write(bytearray("STOP" + "\n", "utf-8"))
                        break
                elif query == "RESET":
                    if isinstance(self.server, AdapterServer):
                        self.server.adapter.reset()
                        self.wfile.write(bytearray("RESET" + "\n", "utf-8"))
                else:
                    if isinstance(self.server, AdapterServer):
                        answer = self.server.adapter.handleQuery(query)
                        self.logger.info("Sending answer: " + answer)
                        self.wfile.write(bytearray(answer + "\n", "utf-8"))
            else:
                return
        sys.exit(0)


class AdapterServer(socketserver.TCPServer):
    def __init__(self, config, handler_class=QueryRequestHandler):
        self.adapter = Adapter(
            str(config["impAddress"]),
            config["impPort"],
            config["timeout"],
            config["interface"],
            config["oracleTableURL"],
        )
        self.adapter.tracker.start()
        self.logger = logging.getLogger("Server")
        self.logger.info("Initialising server...")
        socketserver.TCPServer.__init__(
            self, ("0.0.0.0", config["port"]), handler_class
        )
        return

    def handle_error(self, request, client_address):
        print("-" * 40, file=sys.stderr)
        print(
            "Exception occurred during processing of request from",
            client_address,
            file=sys.stderr,
        )
        import traceback

        traceback.print_exc()
        print("-" * 40, file=sys.stderr)
        print("Crashing...")
        sys.exit(1)


def loadConfig(path):
    with open(path, "r") as stream:
        return yaml.safe_load(stream)["adapter"]


config = loadConfig("/root/config.yaml")
server = AdapterServer(config, QueryRequestHandler)

if __name__ == "__main__":
    server.serve_forever()
