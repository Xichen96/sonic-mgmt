import logging
import os
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


logger = logging.getLogger(__name__)

ALIGN_RESTART_ENV = "SONIC_MGMT_ALIGN_MEMORY_CHECKER_RESTART"


def _get_collection_time(duthost, container_name):
    service = "container_memory_{}".format(container_name)
    result = duthost.shell(
        "sudo monit status {} | sed -n 's/^  data collected *//p'".format(service),
        module_ignore_errors=True,
        verbose=False,
    )
    if result["rc"] != 0:
        return None
    return result["stdout"].strip() or None


def align_memory_checker_restart(duthost, container_name, lead_seconds):
    if os.getenv(ALIGN_RESTART_ENV) != "1":
        return

    initial = _get_collection_time(duthost, container_name)
    pytest_assert(initial, "Unable to read Monit collection time for {}".format(container_name))
    latest = {}

    def _next_cycle_collected():
        current = _get_collection_time(duthost, container_name)
        if current and current != initial:
            latest["value"] = current
            return True
        return False

    pytest_assert(
        wait_until(75, 1, 0, _next_cycle_collected),
        "Monit did not collect a new {} memory sample".format(container_name),
    )
    logger.info(
        "Aligned %s restart from Monit collections %s -> %s; waiting %ss before replacement",
        container_name,
        initial,
        latest["value"],
        lead_seconds,
    )
    time.sleep(lead_seconds)
