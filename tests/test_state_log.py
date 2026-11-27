import logging
import unittest
from unittest import mock

from bgp_antifilter.state_log import StateLog


class StateLogTests(unittest.TestCase):
    def test_repeated_startup_wait_warns_once_after_grace_then_reports_recovery(self):
        logger = mock.Mock()
        state = StateLog(logger, "DNS readiness")
        with mock.patch("bgp_antifilter.state_log.time.monotonic", side_effect=[0, 5, 59, 60, 120]):
            for _ in range(5):
                state.failure("Waiting for initial route policy")
        self.assertEqual([call.args[0] for call in logger.log.call_args_list], [logging.INFO, logging.WARNING])
        state.healthy()
        state.healthy()
        logger.info.assert_called_once()

    def test_distinct_errors_remain_visible(self):
        logger = mock.Mock()
        state = StateLog(logger, "Route maintenance")
        for message in ["BGP down", "BGP down", "Disk full", "Disk full"]:
            state.failure(message)
        self.assertEqual(logger.log.call_count, 2)
