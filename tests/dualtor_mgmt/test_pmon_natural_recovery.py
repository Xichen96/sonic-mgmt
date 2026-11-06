import json
import logging
import shlex
import time
import uuid

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.dualtor_mgmt import test_pmon_responder_order as ordering_diag


pytestmark = [pytest.mark.topology("dualtor"), pytest.mark.dualtor_skip_setup_mux_ports]
logger = logging.getLogger(__name__)


def read_health(host, ports):
    script = (
        "import json; from swsscommon import swsscommon; "
        "from sonic_py_common import daemon_base; "
        "table = swsscommon.Table(daemon_base.db_connect('STATE_DB'), 'MUX_LINKMGR_TABLE'); "
        "print(json.dumps({port: dict(table.get(port)[1]).get('state') for port in "
        + repr(ports) + "}))"
    )
    states = json.loads(host.shell("python3 -c " + shlex.quote(script))["stdout"])
    pytest_assert(set(states) == set(ports) and all(
        value in ("healthy", "unhealthy", "uninitialized") for value in states.values()),
        "Unexpected linkmgrd health schema on {}: {}".format(host.hostname, states))
    return states


def service_identities(hosts):
    identities = {}
    for host in hosts:
        containers = host.shell(
            "docker inspect --format '{{.Id}} {{.State.StartedAt}}' mux pmon")["stdout"].splitlines()
        pytest_assert(len(containers) == 2, "Missing mux/PMON container identity on {}".format(host.hostname))
        for container, service in (("mux", "linkmgrd"), ("pmon", "ycabled")):
            pid = host.shell("docker exec {} supervisorctl pid {}".format(container, service))["stdout"].strip()
            pytest_assert(pid.isdigit() and int(pid) > 0, "Service is not running: {}".format(service))
            stat = host.shell("docker exec {} cat /proc/{}/stat".format(container, pid))["stdout"]
            start_ticks = stat.rpartition(")")[2].split()[19]
            identities[host.hostname + "/" + service] = (
                containers[0 if container == "mux" else 1], pid, start_ticks)
    return identities


def observe_natural_recovery(hosts, ports, token, timeout=1800):
    before = service_identities(hosts)
    started = time.monotonic()
    previous = None
    recovered = False
    ordering_diag.mark(hosts, token, "natural_observation_started")
    while True:
        snapshot = {host.hostname: read_health(host, ports) for host in hosts}
        elapsed = time.monotonic() - started
        if snapshot != previous:
            logger.info("PMON_NATURAL elapsed=%.3f health=%s", elapsed, json.dumps(snapshot))
            previous = snapshot
        recovered = all(value == "healthy" for states in snapshot.values() for value in states.values())
        if recovered or elapsed >= timeout:
            break
        time.sleep(5)
    after = service_identities(hosts)
    ordering_diag.mark(hosts, token, "natural_recovered" if recovered else "natural_observation_timeout")
    logger.info("PMON_NATURAL recovered=%s elapsed=%.3f identities_before=%s identities_after=%s",
                recovered, elapsed, json.dumps(before), json.dumps(after))
    pytest_assert(before == after, "A daemon restarted during natural-recovery observation")
    pytest_assert(recovered,
                  "No all-port natural recovery within the observation budget; inspect timer/packet evidence")


def test_natural_recovery_after_late_pmon(
        duthosts, ptfhost, tbinfo, request, mux_server_url, vmhost, monkeypatch):
    """Extend only C's passive observation, before any restoration or reset."""
    hosts = [duthosts[0], duthosts[1]]
    ports = list(ordering_diag.mux_status(hosts[0]))
    pytest_assert(len(ports) == 24, "This diagnostic requires the original 24-port shape")
    for host in hosts:
        read_health(host, ports)
    token = "natural-after-C-" + uuid.uuid4().hex[:8]
    original_observe = ordering_diag.observe
    original_stop = ordering_diag.stop_before_server_fault
    boundary_reached = [False]
    observation_reached = [False]

    def record_boundary(interface):
        boundary_reached[0] = True
        original_stop(interface)

    def extend_observation(label, observed_hosts, pmon_absent_host=None):
        original_observe(label, observed_hosts, pmon_absent_host=pmon_absent_host)
        if label == "original-startup-outcome":
            pytest_assert(not boundary_reached[0], "C did not reproduce the original blocked startup")
            observation_reached[0] = True
            observe_natural_recovery(observed_hosts, ports, token)
            original_observe("natural-recovery-outcome", observed_hosts)

    monkeypatch.setattr(ordering_diag, "stop_before_server_fault", record_boundary)
    monkeypatch.setattr(ordering_diag, "observe", extend_observation)
    ordering_diag.test_ordered_recovery(
        duthosts, ptfhost, tbinfo, request, mux_server_url, vmhost, "pmon-late")
    pytest_assert(observation_reached[0], "Natural observation was not reached")
