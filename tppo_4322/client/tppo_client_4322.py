import aioconsole
import asyncio
import logging
import sys


logger = logging.getLogger(__name__)


class IoTClientProtocol:
    """
    Client protocol to send queries to an IoT server and receive answers from it.
    """

    def __init__(self, on_con_lost):
        self.on_con_lost = on_con_lost
        self.transport = None

    def connection_made(self, transport):
        """
        Called when a connection is made.
        https://docs.python.org/3/library/asyncio-protocol.html#asyncio.BaseProtocol.connection_made

        :param transport: UDP transport.

        """
        self.transport = transport

    def datagram_received(self, data, addr):
        """
                Called when a datagram is received.
                    https://docs.python.org/3/library/asyncio-protocol.html#asyncio.DatagramProtocol.datagram_received

                :param data: A bytes object containing the incoming data.
                :param addr: The address of the peer sending the data.

        """

        response = eval(data.decode())
        print(f"Received: {response['Message']}")

    def error_received(self, exc):
        logger.error(f'Error received: {exc}')

    def connection_lost(self, exc):
        print("Connection closed")
        self.on_con_lost.set_result(True)


async def main(server_host: str, server_port: int):
    """
    Start client app.

    :param server_host: Server host to connect, defaults to 127.0.0.0.
    :param server_port: Server port to connect, defaults to 54321.

    """
    try:
        loop = asyncio.get_running_loop()
        on_con_lost = loop.create_future()

        logger.debug("Creating client datagram endpoint.")
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: IoTClientProtocol(on_con_lost),
            remote_addr=(server_host, server_port))

        while True:
            query: str = await aioconsole.ainput('Insert your query\n')
            logger.debug(f"Query: {query}.")

            print('Sent:', query)
            transport.sendto(query.encode())
            await asyncio.sleep(0.2)

        # await on_con_lost
    except Exception as e:
        logger.error(f"Error running client: {e}.")
    finally:
        try:
            transport.close()
        except:
            pass

if __name__ == '__main__':

    logging.basicConfig(level=logging.DEBUG)

    n = len(sys.argv)
    if n == 3:
        asyncio.run(main(sys.argv[1], int(sys.argv[2])))
    elif n == 1:
        asyncio.run(main("127.0.0.1", 54321))
    else:
        raise IOError("Incorrect number of arguments! Either pass server host and port or pass nothing.")
