import unittest
from scanner import audit

class ScannerTests(unittest.TestCase):
    def test_security_cases(self):
        self.assertEqual(audit({"SecurityGroups":[{"GroupId":"sg-x","IpPermissions":[{"IpProtocol":"-1","Ipv6Ranges":[{"CidrIpv6":"::/0"}]}]}]})[0]["severity"], "HIGH")
        self.assertEqual(audit({"SecurityGroups":[{"GroupId":"sg-x","IpPermissions":[{"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":"10.0.0.0/8"}]}]}]}), [])

if __name__ == "__main__":
    unittest.main()

