import json
import logging
import os
import shlex
import time
import uuid
from contextlib import ExitStack

import pytest

from tests.common.dualtor.dual_tor_utils import lower_tor_host, upper_tor_host  # noqa: F401
from tests.common.fixtures.ptfhost_utils import run_garp_service, run_icmp_responder  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("dualtor"),
    pytest.mark.usefixtures("run_garp_service", "run_icmp_responder"),
]
logger = logging.getLogger(__name__)


def mux_status(host):
    return json.loads(host.shell("show muxcable status --json")["stdout"])["MUX_CABLE"]


def ready(upper, lower):
    upper_status, lower_status = mux_status(upper), mux_status(lower)
    return (
        len(upper_status) == len(lower_status) == 24
        and all(p["STATUS"] == "active" and p["HEALTH"] == "healthy" for p in upper_status.values())
        and all(p["STATUS"] == "standby" and p["HEALTH"] == "healthy" for p in lower_status.values())
    )


def snapshot(label, hosts):
    logger.info("BACKOFF_DIAG phase=%s epoch=%.6f", label, time.time())
    for host in hosts:
        commands = [
            "show muxcable status --json",
            'sonic-db-cli CONFIG_DB HGETALL "MUX_LINKMGR|LINK_PROBER"',
            'sonic-db-cli STATE_DB HGETALL "PORT_TABLE|Ethernet36"',
            "sonic-db-cli APPL_DB HGETALL MUX_CABLE_RESPONSE_TABLE:Ethernet36",
            "docker exec mux supervisorctl status linkmgrd",
            "docker exec teamd supervisorctl status",
            "docker exec pmon supervisorctl status ycabled",
            "tail -n 1000 /var/log/mux.log",
            "tail -n 1000 /var/log/syslog",
        ]
        result = host.shell_cmds(cmds=commands, timeout=15, continue_on_fail=True)
        logger.info("BACKOFF_DIAG snapshot=%s host=%s result=%s", label, host.hostname,
                    json.dumps(result, default=str))


def set_interval(hosts, interval):
    for host in hosts:
        host.shell('sonic-db-cli CONFIG_DB HSET "MUX_LINKMGR|LINK_PROBER" interval_v4 {}'.format(interval))


def reset_suspend(hosts, ports):
    value = shlex.quote(",".join(ports))
    for host in hosts:
        host.shell('sonic-db-cli CONFIG_DB HSET "MUX_LINKMGR|LINK_PROBER" reset_suspend_timer {}'.format(value))


def restore_probe_state(hosts, ptfhost, ports):
    status = ptfhost.shell("supervisorctl status icmp_responder", module_ignore_errors=True)
    if status["rc"] != 0 or "RUNNING" not in status["stdout"]:
        ptfhost.shell("supervisorctl start icmp_responder")
    set_interval(hosts, 100)
    reset_suspend(hosts, ports)
    for host in hosts:
        host.shell('sonic-db-cli CONFIG_DB HDEL "MUX_LINKMGR|LINK_PROBER" reset_suspend_timer')
    pytest_assert(wait_until(120, 3, 0, ready, hosts[0], hosts[1]), "Diagnostic restoration did not recover mux health")


def start_capture(host, interface, token):
    path = "/tmp/{}-{}.pcap".format(token, host.hostname)
    command = (
        "nohup timeout 1200 tcpdump -U -n -s 256 -i {} 'icmp and host 10.1.0.36' -w {}"
        " > {}.log 2>&1 < /dev/null & echo $!"
    ).format(shlex.quote(interface), shlex.quote(path), shlex.quote(path))
    pid = int(host.shell(command)["stdout"].strip())

    def listening():
        return host.shell("kill -0 {} && grep -q 'listening on' {}.log".format(pid, shlex.quote(path)),
                          module_ignore_errors=True)["rc"] == 0

    if not wait_until(10, 1, 0, listening):
        logger.error("BACKOFF_DIAG capture start failed: %s", host.shell(
            "cat {}.log".format(shlex.quote(path)), module_ignore_errors=True))
        host.shell("kill -TERM {}".format(pid), module_ignore_errors=True)
        pytest.fail("Packet capture did not become ready on {}".format(host.hostname))
    return path, pid


def stop_collect_capture(host, capture, destination):
    path, pid = capture
    result = host.shell("kill -INT {}".format(pid), module_ignore_errors=True)
    logger.info("BACKOFF_DIAG capture_stop host=%s result=%s", host.hostname, result)

    def stopped():
        command = "! kill -0 {} && grep -q 'packets captured' {}.log".format(pid, shlex.quote(path))
        return host.shell(command, module_ignore_errors=True)["rc"] == 0

    pytest_assert(wait_until(10, 1, 0, stopped), "Capture process did not stop on {}".format(host.hostname))
    decode = (
        "tcpdump -tt -nn -r {p} > {p}.txt 2> {p}.decode.err; result=$?; "
        "cat {p}.decode.err; if [ \"$result\" -ne 0 ]; then exit \"$result\"; fi; "
        "awk '{{b=int($1/5)*5; if ($0 ~ /echo request/) req[b]++; "
        "if ($0 ~ /echo reply/) rep[b]++; all[b]++}} "
        "END {{for (b in all) print b, req[b]+0, rep[b]+0}}' {p}.txt | sort -n; "
        "tail -n 80 {p}.txt"
    ).format(p=shlex.quote(path))
    logger.info("BACKOFF_DIAG capture host=%s summary=%s", host.hostname, host.shell(decode))
    for suffix in ("", ".log", ".txt", ".decode.err"):
        host.fetch(src=path + suffix, dest=destination + os.sep, flat=True)
        host.file(path=path + suffix, state="absent")


@pytest.mark.dualtor_active_standby_toggle_to_upper_tor
def test_original_responder_gap(upper_tor_host, lower_tor_host, ptfhost, tbinfo):  # noqa: F811
    hosts = [upper_tor_host, lower_tor_host]
    ports = list(mux_status(hosts[0]))
    pytest_assert(wait_until(120, 3, 0, ready, *hosts), "Diagnostic baseline is not healthy")
    token = "backoff-diag-" + uuid.uuid4().hex[:12]
    destination = os.path.join("logs", "dualtor_mgmt", token)
    os.makedirs(destination)
    ptf_index = hosts[0].get_extended_minigraph_facts(tbinfo)["minigraph_ptf_indices"]["Ethernet36"]

    with ExitStack() as cleanup:
        cleanup.callback(restore_probe_state, hosts, ptfhost, ports)
        for host, interface in [(hosts[0], "Ethernet36"), (hosts[1], "Ethernet36"),
                                (ptfhost, "eth{}".format(ptf_index))]:
            capture = start_capture(host, interface, token)
            cleanup.callback(stop_collect_capture, host, capture, destination)

        snapshot("healthy_baseline", hosts)
        ptfhost.shell("supervisorctl stop icmp_responder")
        off_started = time.monotonic()
        set_interval(hosts, 100)
        logger.info("BACKOFF_DIAG phase=responder_stopped epoch=%.6f", time.time())
        while time.monotonic() - off_started < 430:
            time.sleep(min(30, max(0, 430 - (time.monotonic() - off_started))))
        snapshot("before_interval_change", hosts)
        while time.monotonic() - off_started < 464:
            time.sleep(min(30, max(0, 464 - (time.monotonic() - off_started))))
        set_interval(hosts, 3000)
        logger.info("BACKOFF_DIAG phase=interval_3000 epoch=%.6f", time.time())
        while time.monotonic() - off_started < 472:
            time.sleep(min(1, max(0, 472 - (time.monotonic() - off_started))))
        ptfhost.shell("supervisorctl start icmp_responder")
        snapshot("responder_restarted_no_reset", hosts)
        samples = []
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            state = [mux_status(host) for host in hosts]
            samples.append(state)
            logger.info("BACKOFF_DIAG phase=no_reset_sample epoch=%.6f state=%s", time.time(), json.dumps(state))
            time.sleep(1)

        reproduced = bool(samples) and all(
            all(p["STATUS"] == "active" and p["HEALTH"] == "unhealthy" for p in state[0].values())
            and all(p["STATUS"] == "standby" and p["HEALTH"] == "unhealthy" for p in state[1].values())
            for state in samples
        )
        snapshot("before_suspend_reset", hosts)
        reset_suspend(hosts, ports)
        logger.info("BACKOFF_DIAG phase=suspend_reset epoch=%.6f", time.time())
        recovered = wait_until(45, 1, 0, ready, *hosts)
        snapshot("after_suspend_reset", hosts)
        logger.info("BACKOFF_DIAG reproduced=%s recovered=%s", reproduced, recovered)
        pytest_assert(reproduced, "Exact original all-port unhealthy signature was not reproduced in this smoke")
        pytest_assert(recovered, "Clearing heartbeat suspension alone did not recover mux health")
