import unittest 
import vxlan_setup 


class TestVxlanStup(unittest.TestCase):
    def test_vxlan_setup(self):
        self.assertTrue(vxlan_setup.setup_vxlan("1.1.1.1", 1000, "eth0"))
        vxlan_setup.delete_vxlan("vxlan_{}".format(1000))
    
if __name__ == "__main__":
    unittest.main()