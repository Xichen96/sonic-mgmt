import json
import logging
import os
import shlex
import uuid
from contextlib import ExitStack

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.dualtor_mgmt.test_probe_backoff_diagnostic import start_capture, stop_collect_capture


logger = logging.getLogger(__name__)
MODULES = (
    "dualtor/test_switchover_faulty_ycable.py",
    "arp/test_arp_extended.py",
    "dualtor_mgmt/test_server_failure.py",
)
MARKER = "/tmp/dualtor-probe-history-08f7a1e3.json"


def start_syslog(host, token):
    path = "/tmp/{}-{}.syslog".format(token, host.hostname)
    command = "nohup timeout 1800 tail -n 0 -F /var/log/syslog > {} 2> {}.err < /dev/null & echo $!"
    pid = int(host.shell(command.format(shlex.quote(path), shlex.quote(path)))["stdout"].strip())
    pytest_assert(host.shell("kill -0 {}".format(pid), module_ignore_errors=True)["rc"] == 0,
                  "Passive syslog capture did not start")
    return {"kind": "syslog", "host": host.hostname, "path": path, "pid": pid}


def stop_collect_syslog(host, resource, destination):
    path, pid = resource["path"], resource["pid"]
    result = host.shell("kill -TERM {}".format(pid), module_ignore_errors=True)
    logger.info("PROBE_HISTORY stop_syslog host=%s result=%s", host.hostname, result)

    def stopped():
        return host.shell("kill -0 {}".format(pid), module_ignore_errors=True)["rc"] != 0

    pytest_assert(wait_until(10, 1, 0, stopped), "Passive syslog capture did not stop")
    command = (
        "awk '/linkmgrd/ && (/Ethernet36/ || /interval_v4/ || /reset heartbeat/)' {} | tail -n 2000"
    ).format(shlex.quote(path))
    logger.info("PROBE_HISTORY syslog host=%s result=%s", host.hostname, host.shell(command))
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
                cleanup.callback(stop_collect_syslog, host, resource, destination)


@pytest.fixture(scope="session", autouse=True)
def capture_original_dualtor_history(request, duthosts, ptfhost, tbinfo):
    module = next((name for name in MODULES if any(name in str(arg) for arg in request.config.args)), None)
    if module is None or "dualtor" not in tbinfo["topo"]["name"]:
        yield
        return
    exists = ptfhost.stat(path=MARKER)["stat"]["exists"]
    if exists:
        pytest_assert(module != MODULES[0], "Unexpected capture marker from a previous sequence")
        state = json.loads(ptfhost.shell("cat " + MARKER)["stdout"])
        pytest_assert(state["last_module"] == MODULES[MODULES.index(module) - 1],
                      "Diagnostic modules did not execute in the original order")
    else:
        pytest_assert(module == MODULES[0], "Original-sequence capture marker is missing")
        token = "probe-history-" + uuid.uuid4().hex[:12]
        config = json.loads(duthosts[0].shell("show mux config --json")["stdout"])
        server_ip = config["MUX_CABLE"]["PORTS"]["Ethernet36"]["SERVER"]["IPv4"].split("/")[0]
        state = {"token": token, "resources": [], "last_module": None}
    with ExitStack() as rollback:
        rollback.callback(harvest, state["resources"], state["token"], duthosts, ptfhost)
        if not exists:
            for host in duthosts:
                state["resources"].append(start_syslog(host, token))
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
    if module == MODULES[-1] or request.session.testsfailed:
        harvest(state["resources"], state["token"], duthosts, ptfhost)
