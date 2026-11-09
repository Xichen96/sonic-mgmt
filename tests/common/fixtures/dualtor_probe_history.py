import json
import logging
import os
import shlex
import uuid
from contextlib import ExitStack

import pytest

from ansible.errors import AnsibleConnectionFailure
from tests.common.errors import RunAnsibleModuleFail
from tests.common.helpers.assertions import pytest_assert as assert_condition
from tests.common.utilities import wait_until
from tests.dualtor_mgmt.test_probe_backoff_diagnostic import snapshot, start_capture, stop_collect_capture


logger = logging.getLogger(__name__)
MODULES = (
    "dualtor/test_switchover_faulty_ycable.py",
    "arp/test_arp_extended.py",
    "dualtor_mgmt/test_server_failure.py",
)
MARKER = "/tmp/dualtor-probe-history-08f7a1e3.json"


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when != "call" or not report.failed or MODULES[-1] not in str(item.path):
        return
    fixtures = item.funcargs
    try:
        snapshot("original_failure_before_teardown", [fixtures["duthosts"][0], fixtures["duthosts"][1]])
        ptf = fixtures["ptfhost"]
        commands = [
            "supervisorctl status icmp_responder",
            "cat /tmp/icmp_responder.err.log",
            "ip -details link show",
            "ss -0 -a -p",
        ]
        result = ptf.shell_cmds(cmds=commands, timeout=10, continue_on_fail=True, module_ignore_errors=True)
        logger.warning("PROBE_HISTORY failure_ptf=%s", result)
        group = shlex.quote(fixtures["tbinfo"]["group-name"])
        command = (
            'vmset={}; bridges="$(timeout 10 ovs-vsctl list-br)" || exit $?; '
            'for bridge in $bridges; do case "$bridge" in "mbr-$vmset-"*) '
            'echo "$bridge"; timeout 10 ovs-ofctl --names dump-flows "$bridge"; '
            'status=$?; if [ "$status" -ne 0 ]; then exit "$status"; fi;; esac; done'
        ).format(group)
        logger.warning("PROBE_HISTORY failure_ovs=%s",
                       fixtures["vmhost"].shell(command, module_ignore_errors=True))
    except (RunAnsibleModuleFail, AnsibleConnectionFailure):
        logger.exception("PROBE_HISTORY failure-stage diagnostic read failed; original test failure is preserved")


def start_syslog(host, token):
    path = "/tmp/{}-{}.syslog".format(token, host.hostname)
    command = "nohup timeout 1800 tail -n 0 -F /var/log/syslog > {} 2> {}.err < /dev/null & echo $!"
    pid = int(host.shell(command.format(shlex.quote(path), shlex.quote(path)))["stdout"].strip())
    assert_condition(host.shell("kill -0 {}".format(pid), module_ignore_errors=True)["rc"] == 0,
                     "Passive syslog capture did not start")
    return {"kind": "syslog", "host": host.hostname, "path": path, "pid": pid}


def start_ptf_observer(host, token, label, command):
    path = "/tmp/{}-{}-{}.log".format(token, host.hostname, label)
    command = "nohup timeout 1800 {} > {} 2> {}.err < /dev/null & echo $!".format(
        command, shlex.quote(path), shlex.quote(path))
    pid = int(host.shell(command)["stdout"].strip())

    def alive():
        return host.shell("kill -0 {}".format(pid), module_ignore_errors=True)["rc"] == 0

    if not wait_until(3, 1, 1, alive):
        logger.error("PROBE_HISTORY observer_start_failed label=%s result=%s", label,
                     host.shell("cat " + shlex.quote(path) + ".err", module_ignore_errors=True))
        pytest.fail("Passive PTF observer did not start: " + label)
    return {"kind": "ptf-" + label, "host": host.hostname, "path": path, "pid": pid}


def stop_collect_text(host, resource, destination):
    path, pid = resource["path"], resource["pid"]
    result = host.shell("kill -TERM {}".format(pid), module_ignore_errors=True)
    logger.info("PROBE_HISTORY stop_syslog host=%s result=%s", host.hostname, result)

    def stopped():
        return host.shell("kill -0 {}".format(pid), module_ignore_errors=True)["rc"] != 0

    assert_condition(wait_until(10, 1, 0, stopped), "Passive syslog capture did not stop")
    if resource["kind"] == "syslog":
        command = (
            "awk '/linkmgrd/ && (/Ethernet36/ || /interval_v4/ || /reset heartbeat/)' {} | tail -n 2000"
        ).format(shlex.quote(path))
    else:
        command = "tail -n 2000 " + shlex.quote(path)
    logger.info("PROBE_HISTORY text kind=%s host=%s result=%s",
                resource["kind"], host.hostname, host.shell(command))
    logger.info("PROBE_HISTORY monitor_stderr kind=%s host=%s result=%s",
                resource["kind"], host.hostname, host.shell("cat " + shlex.quote(path) + ".err"))
    for suffix in ("", ".err"):
        host.fetch(src=path + suffix, dest=destination + os.sep, flat=True)
        host.file(path=path + suffix, state="absent")


def harvest(resources, token, duthosts, ptfhost):
    destination = os.path.join("logs", "dualtor_mgmt", token)
    os.makedirs(destination, exist_ok=True)
    with ExitStack() as cleanup:
        cleanup.callback(ptfhost.file, path=MARKER, state="absent")
        for resource in resources:
            host = ptfhost if resource["host"] == ptfhost.hostname else duthosts[resource["host"]]
            if resource["kind"] == "pcap":
                cleanup.callback(stop_collect_capture, host, (resource["path"], resource["pid"]), destination)
            else:
                cleanup.callback(stop_collect_text, host, resource, destination)


@pytest.fixture(scope="session", autouse=True)
def capture_original_dualtor_history(request, duthosts, ptfhost, tbinfo):
    module = next((name for name in MODULES if any(name in str(arg) for arg in request.config.args)), None)
    if module is None or "dualtor" not in tbinfo["topo"]["name"]:
        yield
        return
    exists = ptfhost.stat(path=MARKER)["stat"]["exists"]
    if exists:
        assert_condition(module != MODULES[0], "Unexpected capture marker from a previous sequence")
        state = json.loads(ptfhost.shell("cat " + MARKER)["stdout"])
        assert_condition(state["last_module"] == MODULES[MODULES.index(module) - 1],
                         "Diagnostic modules did not execute in the original order")
    else:
        assert_condition(module == MODULES[0], "Original-sequence capture marker is missing")
        token = "probe-history-" + uuid.uuid4().hex[:12]
        config = json.loads(duthosts[0].shell("show mux config --json")["stdout"])
        server_ip = config["MUX_CABLE"]["PORTS"]["Ethernet36"]["SERVER"]["IPv4"].split("/")[0]
        state = {"token": token, "resources": [], "last_module": None}
    with ExitStack() as rollback:
        rollback.callback(harvest, state["resources"], state["token"], duthosts, ptfhost)
        if not exists:
            for host in duthosts:
                state["resources"].append(start_syslog(host, token))
            state["resources"].append(start_ptf_observer(ptfhost, token, "links", "ip -ts monitor link"))
            state["resources"].append(start_ptf_observer(
                ptfhost, token, "stderr", "tail -n 0 -F /tmp/icmp_responder.err.log"))
            for host, interface in [(duthosts[0], "Ethernet36"), (duthosts[1], "Ethernet36"), (ptfhost, "any")]:
                path, pid = start_capture(host, interface, token, server_ip)
                state["resources"].append({"kind": "pcap", "host": host.hostname, "path": path, "pid": pid})
        state["last_module"] = module
        ptfhost.copy(content=json.dumps(state), dest=MARKER)
        # Transfer capture ownership to the next module's session until final harvest.
        rollback.pop_all()
    logger.info("PROBE_HISTORY module_start=%s token=%s", module, state["token"])
    yield
    logger.info("PROBE_HISTORY module_end=%s failed=%s", module, request.session.testsfailed)
    # Cleanup-only campaigns have no following module to harvest their captures.
    if (os.environ.get("SONIC_DUALTOR_HISTORY_CLEANUP_ONLY") == "1" or
            module == MODULES[-1] or request.session.testsfailed):
        harvest(state["resources"], state["token"], duthosts, ptfhost)
