from twisted.trial import unittest
from twisted.internet import defer
import imp
import os
import sys
from pyptlib.client import ClientTransportPlugin
from twisted.internet import reactor
from twisted.web.http import HTTPFactory
# TODO Get rid of weird importing by moving fog-client into the fog folder and create a script to run fog-client
dont_write_bytecode = sys.dont_write_bytecode
sys.dont_write_bytecode = True
fog_client = imp.load_source('fog-client', './fog-client')
sys.dont_write_bytecode = dont_write_bytecode
del dont_write_bytecode


class ConfigTest(unittest.TestCase):
    def setUp(self):
        fog_client.pt_setup_logger()

    def test_comments(self):
        """ Config reader should lines starting with # """
        test_string = """
        #test comment
        #ClientTransportPlugin obfs3 obfsproxy managed
        """
        config = fog_client.Config.parse(test_string)
        self.assertTrue('obfs3' not in config.transport_map)

    def test_client_line(self):
        """ Config should add a single pt with the name being obfs3 and the value being ['obfsproxy', 'managed'] """
        test_string = """
        ClientTransportPlugin obfs3 obfsproxy managed
        """
        config = fog_client.Config.parse(test_string)
        self.assertTrue('obfs3' in config.transport_map)
        self.assertEqual(config.transport_map['obfs3'], ['obfsproxy', 'managed'])

    def test_client_line_duplicates(self):
        """ The config should only store one instance of a transport. If multiple are found it is an error """
        test_string = """
        ClientTransportPlugin obfs3 obfsproxy managed
        ClientTransportPlugin obfs3 obfsproxy managed
        """
        self.assertRaises(ValueError, fog_client.Config.parse, test_string)

    def test_alias_line(self):
        """ A line like 'obfs3_flashproxy' should be to a chain of transports """
        test_string = """
        ClientTransportPlugin obfs3 obfsproxy managed
        ClientTransportPlugin flashproxy flashproxy-client --transport obfs3|websocket
        Alias obfs3_flashproxy obfs3|flashproxy
        """
        config = fog_client.Config.parse(test_string)
        self.assertTrue('obfs3_flashproxy' in config.alias_map)
        self.assertEqual(config.alias_map['obfs3_flashproxy'], ['obfs3', 'flashproxy'])

    def test_alias_line_duplicates(self):
        """ If there are duplicate alias lines, its an error """
        test_string = """
        ClientTransportPlugin obfs3 obfsproxy managed
        ClientTransportPlugin flashproxy flashproxy-client --transport obfs3|websocket
        Alias obfs3_flashproxy obfs3|flashproxy
        Alias obfs3_flashproxy obfs3|flashproxy
        """
        self.assertRaises(ValueError, fog_client.Config.parse, test_string)

    def test_alias_line_missing_pt(self):
        """ Make sure that the config class checks that each transport in an alias line exists in the transport_map. """
        test_string = """
        ClientTransportPlugin obfs3 obfsproxy managed
        Alias obfs3_flashproxy obfs3|flashproxy
        """
        self.assertRaises(KeyError, fog_client.Config.parse, test_string)

    def test_map_chains_by_cmdlines(self):
        test_string = """
        ClientTransportPlugin obfs3 obfsproxy managed
        ClientTransportPlugin b64 obfsproxy managed
        ClientTransportPlugin websocket flashproxy-client --register
        Alias b64_b64 b64|b64
        Alias b64_obfs3 b64|obfs3
        Alias obfs3_websocket obfs3|websocket
        """
        config = fog_client.Config.parse(test_string)
        self.assertEquals(config.map_chains_by_cmdlines(), {
            ('obfsproxy', 'managed'): (['b64', 'b64'], ['obfs3', 'websocket'], ['b64', 'obfs3']),
            ('flashproxy-client', '--register'): (['obfs3', 'websocket'],)
        })

class PTFunctionsTest(unittest.TestCase):

    def setUp(self):
        """ Set up a fog_client for b64 and dummy transports """
        self.test_checked_port = False
        test_string = """
        ClientTransportPlugin dummy obfsproxy managed
        ClientTransportPlugin b64 obfsproxy managed
        Alias b64_dummy b64|dummy
        Alias b64_b64 b64|b64
        """
        fog_client.pt_setup_logger()
        PATH = os.getenv('PATH')
        self.old_environ = os.environ.copy()
        _environ = {'PATH': PATH, 'TOR_PT_STATE_LOCATION': '.', 'TOR_PT_MANAGED_TRANSPORT_VER': '1', 'TOR_PT_CLIENT_TRANSPORTS': 'b64_dummy'}
        os.environ.update(_environ)
        configuration = fog_client.Config.parse(test_string)
        pt_method_names = configuration.alias_map.keys()
        client = ClientTransportPlugin()
        client.init(pt_method_names) # Initialize our possible methods to all the chains listed by the fog file and stored in alias map.
        if not client.getTransports():
            fog_client.logger.error("no transports to serve. pt_method_names may be invalid.")
            return 1
        self.fog_instance = fog_client.FogClient(reactor, client, configuration)

    def test_pt_launch_child(self):
        """ All launched transports should callback when completed """
        sub_proc, sub_protocol, methoddefers = self.fog_instance.pt_launch_child(('obfs3',), (['obfs3', 'b64'],), ('obfsproxy', 'managed'))
        return defer.DeferredList(methoddefers)

    def test_pt_require_child_cmethods_ok(self):
        """ Check that pt_require_child can extract the correct cmethod """
        cmethod = fog_client.MethodSpec(name='obfs3', protocol='socks4', addrport=('127.0.0.1', 65261), args=[], opts=[])
        self.assertEqual(self.fog_instance.pt_require_child('dummy', (['b64', 'dummy'],), {'dummy': cmethod}), cmethod)

    def test_pt_require_child_cmethods_bad(self):
        """ If a cmethod does not exist and is requested, pt_require_child should error """
        self.assertRaises(ValueError, self.fog_instance.pt_require_child, 'obfs3', (['obfs3', 'flashproxy'],), {})

    def test_pt_setup_socks_shim(self):
        """ Successful launching a socks shim and that the proxy_deferreds list is added to by pt_setup_socks_shim """
        proxy_deferreds = []
        fact = HTTPFactory()
        test_listening_port = reactor.listenTCP(interface='127.0.0.1', port=0, factory=fact)
        dest_addr_port = ('127.0.0.1', test_listening_port.getHost().port)
        pt_name = "dummy"
        chain = ["dummy", "dummy"]
        success_list = [(True, fog_client.MethodSpec(name='dummy', protocol='socks4', addrport=('127.0.0.1', 58982), args=[], opts=[]))]
        returned_listening_port = self.fog_instance.pt_setup_socks_shim(pt_name, chain, success_list, dest_addr_port, proxy_deferreds)
        self.assertTrue(returned_listening_port.getHost().port)
        self.assertTrue((len(proxy_deferreds) > 0))
        test_listening_port.stopListening()

    def test_pt_launch_chain(self):
        """ Launch chain successfully and check if it returns a correct addr_port """
        dest_addr_port = ('127.0.0.1', 2401)
        chain = ['b64', 'b64', 'b64', 'b64']
        success_list = [(True, fog_client.MethodSpec(name='b64', protocol='socks4', addrport=('127.0.0.1', 53269), args=[], opts=[]))]
        def check_addr_port (addr_port):
            self.test_checked_port = True
            self.assertTrue((len(addr_port) > 1 and type(addr_port[0]) == str and type(addr_port[1]) == int and addr_port[1] <= 65535))
        self.fog_instance.pt_launch_chain(dest_addr_port, chain, check_addr_port, success_list)
        self.assertTrue(self.test_checked_port)

    def test_pt_get_unique_cmdline_list(self):
        unique_list = self.fog_instance.pt_get_unique_cmdline_list()
        self.assertEqual(unique_list, [('obfsproxy', 'managed')])

    def tearDown(self):
        os.environ = self.old_environ
        self.fog_instance.reactor.removeAll()

if __name__ == '__main__':
    unittest.main()
