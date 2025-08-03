import unittest 
import check_wg 


class TestCheckWg(unittest.TestCase):
    def test_check_wg(self):
        self.assertTrue(check_wg.check_wg("wg0"))
    
    def test_get_wg_ip(self):
        self.assertNotEqual(check_wg.get_wg_ip("wg0"), "")

if __name__ == "__main__":
    unittest.main()