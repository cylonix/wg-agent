import unittest 
import routing_setup

class TestRouteSetup(unittest.TestCase):
    def test_enable_forward(self):
        self.assertTrue(routing_setup.enable_forwading())
    def test_route_setup(self):
        self.assertTrue(routing_setup.setup_routing("wg0", 1234))
        routing_setup.clean_routing("wg0", 1234)
if __name__ == "__main__":
    unittest.main()