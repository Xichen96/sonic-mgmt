import inspect
import json
import logging
import os
import re
import shlex
import uuid
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone

import pytest

from tests.common.dualtor import mux_simulator_control as mux_control
from tests.common.dualtor.dual_tor_common import CableType
from tests.common.dualtor.mux_simulator_control import simulator_flap_counter, simulator_server_down  # noqa: F401
from tests.common.fixtures import dualtor_probe_history as history
from tests.common.fixtures import ptfhost_utils
from tests.common.fixtures.ptfhost_utils import run_garp_service  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import check_container_state
from tests.common.utilities import wait_until
from tests.dualtor_mgmt import test_server_failure as original_case
from tests.dualtor_mgmt.test_probe_backoff_diagnostic import (
    mux_status, ready, restore_probe_state, set_interval, snapshot, start_capture, stop_collect_capture,
)


pytestmark = [pytest.mark.topology("dualtor")]
logger = logging.getLogger(__name__)
EVENT = re.compile(
    r"^(\d{4} [A-Za-z]{3}\s+\d{1,2} [\d:.]+) \S+ \S+ mux#linkmgrd:.*"
    r"Ethernet36: (suspend ICMP heartbeat probing|suspend timeout)"
)


@contextmanager
def responder_fixture(duthosts, ptfhost, tbinfo, request, ports):
    function = inspect.unwrap(ptfhost_utils.run_icmp_responder)
    values = {"duthosts": duthosts, "ptfhost": ptfhost, "tbinfo": tbinfo, "request": request,
              "rand_one_dut_hostname": duthosts[0].hostname, "active_standby_ports": ports}
    parameters = inspect.signature(function).parameters
    pytest_assert(set(parameters).issubset(values), "Unexpected responder fixture interface")
    generator = function(**{name: values[name] for name in parameters})
    next(generator)
    try:
        yield
    finally:
        try:
            next(generator)
        except StopIteration:
            pass
        else:
            pytest.fail("Responder fixture unexpectedly yielded twice")


def canonical_restore(hosts, ptfhost, ports):
    restore_probe_state(hosts, ptfhost, ports)
    ptfhost.shell("supervisorctl stop icmp_responder")
    for host in hosts:
        host.shell('sonic-db-cli CONFIG_DB DEL "MUX_LINKMGR|LINK_PROBER"')


def enter_original_pmon_recovery(duthosts, ptfhost, tbinfo, request, ports, hosts):
    pmon_stopping = False
    try:
        with responder_fixture(duthosts, ptfhost, tbinfo, request, ports):
            restore_probe_state(hosts, ptfhost, ports)
            pmon_stopping = True
            hosts[0].shell("systemctl stop pmon.service")
            hosts[0].shell("docker rm pmon")
    finally:
        if pmon_stopping:
            hosts[0].shell("systemctl start pmon.service")
            pytest_assert(wait_until(60, 5, 0, check_container_state, hosts[0], "pmon", True),
                          "Upper PMON did not return after recreation")


def suspend_events(host, path):
    command = (
        "awk '$7 == \"mux#linkmgrd:\" && index($0, \"Ethernet36: suspend\") {{print}}' {} | tail -n 16"
    ).format(shlex.quote(path))
    result = []
    for line in host.shell(command)["stdout"].splitlines():
        match = EVENT.search(line)
        if match:
            timestamp = datetime.strptime(" ".join(match[1].split()), "%Y %b %d %H:%M:%S.%f")
            result.append((timestamp.replace(tzinfo=timezone.utc).timestamp(), match[2]))
    return result


def maximum_backoff(host, path, state):
    events = suspend_events(host, path)
    start = None
    completed = 0
    for timestamp, event in events:
        if event == "suspend ICMP heartbeat probing":
            start = timestamp
        elif start is not None:
            completed = timestamp - start
    if events and events[-1][1] == "suspend ICMP heartbeat probing" and completed >= 25:
        state["last_suspend"] = events[-1][0]
        logger.info("SUSPEND_CONTROL maximum_backoff=%s", events)
        return True
    return False


def next_suspend(host, path, previous):
    events = suspend_events(host, path)
    return bool(events and events[-1][1] == "suspend ICMP heartbeat probing" and events[-1][0] > previous)


@pytest.mark.dualtor_active_standby_toggle_to_upper_tor
def test_original_startup_after_observed_suspend(
        duthosts, ptfhost, tbinfo, request, mux_server_url, vmhost,
        simulator_flap_counter, simulator_server_down):  # noqa: F811
    hosts = [duthosts[0], duthosts[1]]
    ports = list(mux_status(hosts[0]))
    pytest_assert(len(ports) == 24, "This diagnostic requires the original 24-port dualtor shape")
    token = "startup-suspend-" + uuid.uuid4().hex[:12]
    destination = os.path.join("logs", "dualtor_mgmt", token)
    os.makedirs(destination)
    config = json.loads(hosts[0].shell("show mux config --json")["stdout"])
    server_ip = config["MUX_CABLE"]["PORTS"]["Ethernet36"]["SERVER"]["IPv4"].split("/")[0]
    with ExitStack() as cleanup:
        cleanup.callback(canonical_restore, hosts, ptfhost, ports)
        logs = []
        for host in hosts:
            resource = history.start_syslog(host, token)
            logs.append(resource)
            cleanup.callback(history.stop_collect_text, host, resource, destination)
        for host, interface in [(hosts[0], "Ethernet36"), (hosts[1], "Ethernet36"), (ptfhost, "any")]:
            capture = start_capture(host, interface, token, server_ip)
            cleanup.callback(stop_collect_capture, host, capture, destination)
        status = ptfhost.shell("supervisorctl status icmp_responder", module_ignore_errors=True)
        if "RUNNING" in status["stdout"]:
            ptfhost.shell("supervisorctl stop icmp_responder")
        # Preserve warm linkmgrd, with PMON initialization occurring after responder teardown.
        enter_original_pmon_recovery(duthosts, ptfhost, tbinfo, request, ports, hosts)
        mux_control._toggle_all_simulator_ports_to_target_dut(
            hosts[0].hostname, duthosts, mux_server_url, tbinfo, vmhost)
        state = {}
        pytest_assert(wait_until(180, 1, 0, maximum_backoff, hosts[0], logs[0]["path"], state),
                      "The observed exponential suspension path was not reached")
        set_interval(hosts, 3000)
        pytest_assert(wait_until(65, 1, 0, next_suspend, hosts[0], logs[0]["path"], state["last_suspend"]),
                      "No new suspension occurred after the interval transition")
        snapshot("phase_aligned_suspension", hosts)
        with responder_fixture(duthosts, ptfhost, tbinfo, request, ports):
            mux_control._toggle_all_simulator_ports_to_target_dut(
                hosts[0].hostname, duthosts, mux_server_url, tbinfo, vmhost)
            snapshot("original_fixture_started", hosts)
            with pytest.raises(pytest.fail.Exception, match="Test can't proceed") as failure:
                original_case.test_server_down(
                    CableType.active_standby, duthosts, tbinfo, [], ports,
                    simulator_flap_counter, simulator_server_down, None, None, hosts[0], hosts[1], None)
            logger.warning("SUSPEND_CONTROL original_failure=%s", failure.getrepr(style="short"))
            observed = [mux_status(host) for host in hosts]
            pytest_assert(
                all(p["STATUS"] == "active" and p["HEALTH"] == "unhealthy" for p in observed[0].values())
                and all(p["STATUS"] == "standby" and p["HEALTH"] == "unhealthy" for p in observed[1].values()),
                "The failure did not preserve the original all-port mux-health signature")
            snapshot("accepted_original_failure", hosts)
            duthosts.shell("config muxcable reset-heartbeat-suspend all")
            pytest_assert(wait_until(30, 1, 0, ready, *hosts), "Heartbeat reset alone did not recover the failure")
            snapshot("reset_only_recovery", hosts)
            logger.info("SUSPEND_CONTROL accepted_failure=True reset_only_recovery=True")
