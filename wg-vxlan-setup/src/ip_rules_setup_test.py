import unittest 
import ip_rules_setup

class TestIpRuleSetup(unittest.TestCase):
    def test_iptables_setup(self):
        self.assertTrue(ip_rules_setup.setup_ip_rules(1234,1234))
        ip_rules_setup.clear_ip_rule(1234,1234)
    
if __name__ == "__main__":
    unittest.main()