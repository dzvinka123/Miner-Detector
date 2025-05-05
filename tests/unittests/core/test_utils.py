import unittest
import pytest
from core.util import parse_time_threshold, send_report_to_server
from unittest.mock import patch, Mock


class TestUtil(unittest.TestCase):
    def test_parse_time_threshold(self):
        self.assertEqual(parse_time_threshold("24h"), 86400)

    def test_raise_exception_if_not_matched(self):
        with pytest.raises(Exception):
            parse_time_threshold("Happy Halloween")

    def test_send_report_to_server_success(self):
        mock_response = Mock()
        mock_response.status_code = 200
        with patch("requests.post", return_value=mock_response):
            result = send_report_to_server("Send this text into server")
            self.assertEqual(result, 200)


if __name__ == "__main__":
    unittest.main()
