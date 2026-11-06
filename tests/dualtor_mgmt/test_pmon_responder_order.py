import json
import logging
import os
import shlex
import time
import uuid
from contextlib import ExitStack

import pytest

from tests.common.dualtor import mux_simulator_control as mux_control
from tests.common.dualtor.dual_tor_common import CableType
from tests.common.fixtures import dualtor_probe_history as history
from tests.common.fixtures.ptfhost_utils import run_garp_service  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import check_container_state
from tests.common.utilities import wait_until
from tests.dualtor_mgmt import test_server_failure as original_case
from tests.dualtor_mgmt.test_probe_backoff_diagnostic import (
    mux_status, ready, set_interval, start_capture, stop_collect_capture,
)
from tests.dualtor_mgmt.test_startup_suspend_control import (
    canonical_restore, responder_fixture,
)


pytestmark = [pytest.mark.topology("dualtor"), pytest.mark.dualtor_skip_setup_mux_ports]
logger = logging.getLogger(__name__)


class StartupPrerequisiteReached(Exception):
    pass


def stop_before_server_fault(interface):
    raise StartupPrerequisiteReached("startup prerequisite passed for " + interface)


def observe(label, hosts):
    commands = [
        'sonic-db-cli APPL_DB HGETALL "MUX_CABLE_TABLE:Ethernet36"',
        'sonic-db-cli STATE_DB HGETALL "MUX_CABLE_TABLE|Ethernet36"',
        'sonic-db-cli STATE_DB HGETALL "MUX_LINKMGR_TABLE|Ethernet36"',
        'sonic-db-cli APPL_DB HGETALL "HW_MUX_CABLE_TABLE:Ethernet36"',
        'sonic-db-cli STATE_DB HGETALL "HW_MUX_CABLE_TABLE|Ethernet36"',
        'sonic-db-cli APPL_DB HGETALL "MUX_CABLE_RESPONSE_TABLE:Ethernet36"',
        'sonic-db-cli CONFIG_DB HGETALL "MUX_LINKMGR|LINK_PROBER"',
        'docker exec mux supervisorctl status linkmgrd',
        'docker exec pmon supervisorctl status ycabled',
    ]
    for host in hosts:
        result = host.shell_cmds(cmds=commands, timeout=15, continue_on_fail=True)
        logger.info("PMON_ORDER observation=%s host=%s result=%s", label, host.hostname, json.dumps(result))


def mark(hosts, token, phase):
    for host in hosts:
        host.shell("logger -t pmon_order {}".format(shlex.quote(token + " phase=" + phase)))


def collect_history(host, resource, destination):
    path = resource["path"]
    host.shell("kill -TERM {}".format(resource["pid"]), module_ignore_errors=True)
    pytest_assert(wait_until(
        10, 1, 0,
        lambda: host.shell("kill -0 {}".format(resource["pid"]), module_ignore_errors=True)["rc"] != 0),
        "Passive syslog collector did not stop")
    command = (
        "awk '/pmon_order/ || /interval_v4/ || "
        "(/Ethernet36/ && (/mux#linkmgrd/ || /pmon#/ || /swss#orchagent/))' {} | tail -n 1800"
    ).format(shlex.quote(path))
    logger.info("PMON_ORDER history host=%s result=%s", host.hostname, json.dumps(host.shell(command)))
    for suffix in ("", ".err"):
        host.fetch(src=path + suffix, dest=destination + os.sep, flat=True)
        host.file(path=path + suffix, state="absent")


def start_pmon(host, require_ycabled):
    host.shell("systemctl reset-failed pmon.service")
    host.shell("systemctl start pmon.service")

    def started():
        return (check_container_state(host, "pmon", True) and
                (not require_ycabled or host.get_pmon_daemon_status("ycabled")[0] == "RUNNING"))

    pytest_assert(wait_until(60, 1, 0, started), "PMON did not reach the requested startup milestone")


@pytest.mark.parametrize("ordering", ["responder-only", "pmon-ready", "pmon-late"])
def test_ordered_recovery(duthosts, ptfhost, tbinfo, request, mux_server_url, vmhost, ordering):
    hosts = [duthosts[0], duthosts[1]]
    ports = list(mux_status(hosts[0]))
    pytest_assert(len(ports) == 24, "This diagnostic requires the original 24-port dualtor shape")
    token = "pmon-order-" + ordering + "-" + uuid.uuid4().hex[:8]
    destination = os.path.join("logs", "dualtor_mgmt", token)
    os.makedirs(destination)
    config = json.loads(hosts[0].shell("show mux config --json")["stdout"])
    server_ip = config["MUX_CABLE"]["PORTS"]["Ethernet36"]["SERVER"]["IPv4"].split("/")[0]
    with ExitStack() as cleanup:
        def restore_environment():
            if (not check_container_state(hosts[0], "pmon", True) or
                    hosts[0].get_pmon_daemon_status("ycabled")[0] != "RUNNING"):
                start_pmon(hosts[0], require_ycabled=True)
            canonical_restore(hosts, ptfhost, ports)

        cleanup.callback(restore_environment)
        for host in hosts:
            resource = history.start_syslog(host, token)
            cleanup.callback(collect_history, host, resource, destination)
        for host, interface in [(hosts[0], "Ethernet36"), (hosts[1], "Ethernet36"), (ptfhost, "any")]:
            capture = start_capture(host, interface, token, server_ip)
            cleanup.callback(stop_collect_capture, host, capture, destination)
        with responder_fixture(duthosts, ptfhost, tbinfo, request, ports):
            mux_control._toggle_all_simulator_ports_to_target_dut(
                hosts[0].hostname, duthosts, mux_server_url, tbinfo, vmhost)

            def establish_baseline():
                duthosts.shell("config muxcable reset-heartbeat-suspend all")
                return ready(*hosts)

            pytest_assert(wait_until(120, 3, 0, establish_baseline), "Healthy baseline was not established")
            duthosts.shell('sonic-db-cli CONFIG_DB HDEL "MUX_LINKMGR|LINK_PROBER" reset_suspend_timer')
            set_interval(hosts, 3000)
            observe("baseline-" + ordering, hosts)
            mark(hosts, token, "baseline_ready")
            if ordering != "responder-only":
                hosts[0].shell("systemctl stop pmon.service")
                hosts[0].shell("docker rm pmon")
                mark(hosts, token, "pmon_removed")
                if ordering == "pmon-ready":
                    start_pmon(hosts[0], require_ycabled=True)
                    time.sleep(60)
                    probe = hosts[0].shell(
                        "sonic-db-cli APPL_DB HGET MUX_CABLE_RESPONSE_TABLE:Ethernet36 response")["stdout"]
                    peer = hosts[0].shell(
                        'sonic-db-cli STATE_DB HGET "MUX_CABLE_INFO|Ethernet36" link_status_peer')["stdout"]
                    pytest_assert(probe in ("active", "standby") and peer == "up",
                                  "The proposed selected-port restoration condition did not pass")
                    observe("restoration-check-passed", hosts)
                    mark(hosts, token, "restoration_check_passed")
        offline_start = time.monotonic()
        mark(hosts, token, "responder_stopped")
        if ordering == "pmon-late":
            pytest_assert(wait_until(
                20, 1, 0,
                lambda: hosts[1].shell(
                    'sonic-db-cli STATE_DB HGET "MUX_CABLE_TABLE|Ethernet36" state')["stdout"] == "active"),
                "Peer takeover was not observed while upper PMON was absent")
            observe("peer-active-before-pmon-start", hosts)
            start_pmon(hosts[0], require_ycabled=False)
            mark(hosts, token, "late_pmon_started")
        remaining = 180 - (time.monotonic() - offline_start)
        pytest_assert(remaining > 0, "Startup exceeded the common offline observation budget")
        time.sleep(remaining)
        observe("offline-before-interval-change", hosts)
        set_interval(hosts, 3000)
        mark(hosts, token, "interval_3000_responder_still_off")
        # Give all arms the same window for an existing short timer to renew at the larger interval.
        time.sleep(65)
        observe("before-responder-restart", hosts)
        startup_passed = False
        with responder_fixture(duthosts, ptfhost, tbinfo, request, ports):
            mark(hosts, token, "responder_restarted")
            mux_control._toggle_all_simulator_ports_to_target_dut(
                hosts[0].hostname, duthosts, mux_server_url, tbinfo, vmhost)
            try:
                original_case.test_server_down(
                    CableType.active_standby, duthosts, tbinfo, [], ports,
                    stop_before_server_fault, None, None, None, hosts[0], hosts[1], None)
            except StartupPrerequisiteReached:
                startup_passed = True
            except pytest.fail.Exception as error:
                if "Test can't proceed" not in str(error):
                    raise
                logger.info("PMON_ORDER original_startup_blocked=%s", error)
            else:
                pytest.fail("Original testcase returned without reaching the server-fault boundary")
            observe("original-startup-outcome", hosts)
            mark(hosts, token, "measurement_finished")
            logger.info("PMON_ORDER outcome ordering=%s startup_passed=%s", ordering, startup_passed)
        pytest_assert(startup_passed == (ordering != "pmon-late"),
                      "Observed ordering outcome contradicts the proposed PMON startup explanation")
