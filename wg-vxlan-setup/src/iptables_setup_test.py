import unittest 
import iptables_setup


class TestIptablesStup(unittest.TestCase):
    def test_iptables_setup(self):
        self.assertTrue(iptables_setup.setup_iptabels("192.168.0.0/24", "eth0", 1234))
        iptables_setup.clear_iptabels("192.168.0.0/24", "eth0", 1234)
    
if __name__ == "__main__":
    unittest.main()