import unittest
from cli.util import parse_time_threshold


class TestUtil(unittest.TestCase):
    def test_parse_time_threshold(self):
        self.assertEqual(parse_time_threshold("24h"), 86400)


if __name__ == "__main__":
    unittest.main()
