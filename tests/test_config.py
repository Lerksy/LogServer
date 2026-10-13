import os
import unittest
from unittest.mock import patch

from logserver.config import Settings


class SettingsTests(unittest.TestCase):
    def test_live_stream_limit_from_environment(self):
        with patch.dict(os.environ, {"LOGSERVER_MAX_STREAMS_PER_CLIENT": "12"}):
            self.assertEqual(Settings.from_env().max_streams_per_client, 12)

    def test_live_stream_limit_must_be_positive(self):
        with patch.dict(os.environ, {"LOGSERVER_MAX_STREAMS_PER_CLIENT": "0"}):
            with self.assertRaisesRegex(ValueError, "must be a positive integer"):
                Settings.from_env()


if __name__ == "__main__":
    unittest.main()
