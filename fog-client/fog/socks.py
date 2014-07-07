from twisted.protocols import socks
from twisted.internet.protocol import Factory
import logging

logger = logging.getLogger('fog-logger')

class SOCKSv4InterceptorProtocol(socks.SOCKSv4):
    """
    A modified SOCKS protocol which extracts the requested ip and port
    and redirects connections to the first pluggable transport in the chain.
    """

    def __init__(self, factory, pt_method_name):
        """
        :param twisted.internet.protocol.factory factory: The factory that launched this protocol
        :param pt_method_name: The name of the chain to be launched when a new connection is received
        """
        self.factory = factory
        self._pt_method_name = pt_method_name
        socks.SOCKSv4.__init__(self)

    def _dataReceived2(self, server, user, version, code, port):
        """
        Extracts the requested ip and port and redirects to a different address
        """
        if code == 1: # CONNECT
            assert version == 4, "Bad version code: %s" % version
            if not self.authorize(code, server, port, user):
                self.makeReply(91)
                return
            def _chain_set_up(remote_addr_port):
                logger.debug("chain finished, connecting %s" % (remote_addr_port,))
                # Connect to our remote address instead of the requested one
                d = self.connectClass(remote_addr_port[0], remote_addr_port[1], socks.SOCKSv4Outgoing, self)
                d.addErrback(lambda result, self = self: self.makeReply(91))
            self.factory._new_conn_callback((server, port), self._pt_method_name, _chain_set_up)
            assert self.buf == "", "hmm, still stuff in buffer... %s" % repr(self.buf)
        else:
            super(SOCKSv4InterceptorProtocol, self)._dataReceived2(server, user, version, code, port)

class SOCKSv4InterceptorFactory(Factory):

    def __init__(self, pt_method_name, new_conn_callback):
        """
        :param str pt_method_name: The name of the pt_method that this factory is launching.
        :param function new_conn_callback: The function to be called when a connection is made.
            def new_conn_callback
                :param str server: The ip address requested by the SOCKS client.
                :param int port: The port requested by the SOCKS client.
                :param str pt_method_name: The name of the pt_method this factory is a part of.
                :param function chain_set_up: The function to be called when the chain has finished setting up.
                            :param str remote_address: The address to relay the SOCKS request to.
                            :param int remote_port: The port to to send the SOCKS request to.
        """
        self._pt_method_name = pt_method_name
        self._new_conn_callback = new_conn_callback

    def buildProtocol(self, addr):
        return SOCKSv4InterceptorProtocol(self, self._pt_method_name)
