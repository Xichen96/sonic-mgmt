"""
Helper script for checking status of interfaces

This script contains re-usable functions for checking status of interfaces on SONiC.
"""
import logging
from transceiver_utils import all_transceivers_detected


def parse_intf_status(lines):
    """
    @summary: Parse the output of command "show interface description".
    @param lines: The output lines of command "show interface description".
    @return: Return a dictionary like:
        {
            "Ethernet0": {
                "oper": "up",
                "admin": "up",
                "alias": "etp1",
                "desc": "ARISTA01T2:Ethernet1"
            },
            ...
        }
    """
    result = {}
    for line in lines:
        fields = line.split()
        if len(fields) >= 5:
            intf = fields[0]
            oper, admin, alias, desc = fields[1], fields[2], fields[3], ' '.join(fields[4:])
            result[intf] = {"oper": oper, "admin": admin, "alias": alias, "desc": desc}
    return result


def check_interface_status(dut, asic_index, interfaces, xcvr_skip_list):
    """
    @summary: Check the admin and oper status of the specified interfaces on DUT.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    @param interfaces: List of interfaces that need to be checked.
    """
    asichost = dut.asic_instance(asic_index)
    namespace = asichost.get_asic_namespace()
    logging.info("Check interface status using cmd 'show interface'")
    #TODO Remove this logic when minigraph facts supports namespace in multi_asic
    mg_ports = dut.minigraph_facts(host=dut.hostname)["ansible_facts"]["minigraph_ports"]
    if asic_index is not None:
        portmap = get_port_map(dut, asic_index)
        # Check if the interfaces of this AISC is present in mg_ports
        interface_list = {k:v for k, v in portmap.items() if k in mg_ports}
        mg_ports = interface_list
    output = dut.command("show interface description")
    intf_status = parse_intf_status(output["stdout_lines"][2:])
    check_intf_presence_command = 'show interface transceiver presence'
    check_presence_output = dut.command(check_intf_presence_command)["stdout_lines"]
    for intf in interfaces:
        expected_oper = "up" if intf in mg_ports else "down"
        expected_admin = "up" if intf in mg_ports else "down"
        if intf not in intf_status:
            logging.info("Missing status for interface %s" % intf)
            return False
        if intf_status[intf]["oper"] != expected_oper:
            logging.info("Oper status of interface %s is %s, expected '%s'" % (intf, intf_status[intf]["oper"],
                                                                               expected_oper))
            return False
        if intf_status[intf]["admin"] != expected_admin:
            logging.info("Admin status of interface %s is %s, expected '%s'" % (intf, intf_status[intf]["admin"],
                                                                                expected_admin))
            return False

        # Cross check the interface SFP presence status
        if intf not in xcvr_skip_list[dut.hostname]:
            check_presence_output = dut.command(check_intf_presence_command.format(intf))
            presence_list = check_presence_output["stdout_lines"][2].split()
            assert intf in presence_list, "Wrong interface name in the output: %s" % str(presence_list)

    logging.info("Check interface status using the interface_facts module")
    intf_facts = dut.interface_facts(up_ports=mg_ports, namespace=namespace)["ansible_facts"]
    down_ports = intf_facts["ansible_interface_link_down_ports"]
    if len(down_ports) != 0:
        logging.info("Some interfaces are down: %s" % str(down_ports))
        return False

    return True

# This API to check the interface information actoss all front end ASIC's
def check_all_interface_information(dut, interfaces, xcvr_skip_list):
    transceivers = dut.command("bash -c \"show interface transceiver presence | grep Present\"")
    for asic_index in dut.get_frontend_asic_ids():
        # Get the interfaces pertaining to that asic
        interface_list = get_port_map(dut, asic_index)
        interfaces_per_asic = {k:v for k, v in interface_list.items() if k in interfaces}
        transceiver_interfaces = [intf for intf in interfaces_per_asic if intf in transceivers]
        if not all_transceivers_detected(dut, asic_index, transceiver_interfaces, xcvr_skip_list):
            logging.info("Not all transceivers are detected")
            return False
        if not check_interface_status(dut, asic_index, interfaces_per_asic, xcvr_skip_list):
            logging.info("Not all interfaces are up")
            return False

    return True

# This API to check the interface information per asic.
def check_interface_information(dut, asic_index, interfaces, xcvr_skip_list):
    if not all_transceivers_detected(dut, asic_index, interfaces, xcvr_skip_list):
        logging.info("Not all transceivers are detected on asic %s" % asic_index)
        return False
    if not check_interface_status(dut, asic_index, interfaces, xcvr_skip_list):
        logging.info("Not all interfaces are up on asic %s" % asic_index)
        return False

    return True

def get_port_map(dut, asic_index=None):
    """
    @summary: Get the port mapping info from the DUT
    @return: a dictionary containing the port map
    """
    logging.info("Retrieving port mapping from DUT")
    namespace = dut.get_namespace_from_asic_id(asic_index)
    config_facts = dut.config_facts(host=dut.hostname, source="running",namespace=namespace)['ansible_facts']
    port_mapping = config_facts['port_index_map']
    for k,v in port_mapping.items():
        port_mapping[k] = [v]

    return port_mapping
