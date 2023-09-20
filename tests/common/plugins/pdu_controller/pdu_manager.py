"""
    PduManager is intended to solve the issue where DUT connects to
    multiple PDU controllers.

    It also intended to hide the dependency on the fake outlet_id,
    and reference outlet buy outlet dictionary directly. With this,
    we could enable different way to identify outlet, e.g. with the
    outlet number from graph.

    It also intended to create a smooth transition from defining
    PDU in inventory to defining PDU in connection graph. Data in
    graph is preferred, but if graph data is missing, existing
    inventory data will be used.

    PDU manager implements the same base PDU controller APIs and
    collect status from and distribute operations to individual PDU
    controllers.
"""

import logging
from .snmp_pdu_controllers import get_pdu_controller

logger = logging.getLogger(__name__)


class PSU():

    def __init__(self, psu_name, dut_name):
        self.psu_name = psu_name
        self.dut_name = dut_name

    def build_psu(self, psu_peer, pdu_vars):
        self.feeds = {}
        for feed_name, psu_peer_of_feed in psu_peer.items():
            feed = Feed(self, feed_name)
            if feed.build_feed(psu_peer_of_feed, pdu_vars[feed_name]):
                self.feeds[feed_name] = feed
        return len(self.feeds) > 0


class Feed():

    controllers = {}

    def __init__(self, psu, feed_name):
        self.psu = psu
        self.feed_name = feed_name

    def build_feed(self, psu_peer_of_feed, pdu_vars):
        if 'ManagementIp' not in psu_peer_of_feed or 'Protocol' not in psu_peer_of_feed:
            logger.warning('PSU {} feed {} is missing critical information'.format(self.psu.psu_name, self.feed_name))
            return False
        if psu_peer_of_feed['Protocol'] != 'snmp':
            logger.warning('Protocol {} is currently not supported'.format(psu_peer_of_feed['Protocol']))
            return False
        self.hostname = psu_peer_of_feed['Hostname']
        self.ip = psu_peer_of_feed['ManagementIp']
        self.protocol = psu_peer_of_feed['Protocol']
        self.hwsku = psu_peer_of_feed['HwSku']
        self.type = psu_peer_of_feed['Type']
        self.psu_peer = psu_peer_of_feed
        if not self._build_controller(pdu_vars):
            return False
        outlet = None
        # if peerport is probing/not given, return status of all ports on the pdu
        peerport = psu_peer_of_feed.get('peerport', 'probing')
        if peerport != 'probing':
            outlet = peerport if peerport.startswith('.') else '.' + peerport
        outlets = self.controller.get_outlet_status(hostname=self.psu.dut_name, outlet=outlet)
        for outlet in outlets:
            outlet['pdu_name'] = self.hostname
            outlet['psu_name'] = self.psu.psu_name
            outlet['feed_name'] = self.feed_name
        self.outlets = outlets
        return len(self.outlets) > 0

    def _build_controller(self, pdu_vars):
        if self.ip in Feed.controllers:
            self.controller = Feed.controllers[self.ip]
        else:
            self.controller = get_pdu_controller(self.ip, pdu_vars, self.hwsku, self.type)
            if not self.controller:
                logger.warning('Failed creating pdu controller: {}'.format(self.psu_peer))
                return False
            Feed.controllers[self.ip] = self.controller
        return True


class PduManager():

    def __init__(self, dut_hostname):
        """
            dut_hostname is the target DUT host name. The dut
            defines which PDU(s) and outlet(s) it connected to.

            It is NOT the PDU host name. PDU host name is defined
            either in graph or in inventory and associated with
            the DUT.
        """
        self.dut_hostname = dut_hostname
        """
        A PSU instance represents a PSU. A PSU can have multiple feeds,
        where all of them contributes to the status of one PSU.
        """
        self.PSUs = {}

    def add_controller(self, psu_name, psu_peer, pdu_vars):
        """
            Add a controller to be managed.
            Sample psu_peer:
            {
                "A": {
                    "peerdevice": "pdu-107",
                    "HwSku": "Sentry",
                    "Protocol": "snmp",
                    "ManagementIp": "10.0.0.107",
                    "Type": "Pdu",
                    "peerport": "39",
                }
            }
        """
        psu = PSU(psu_name, self.dut_hostname)
        if not psu.build_psu(psu_peer, pdu_vars):
            return
        self.PSUs[psu_name] = psu

    def _get_controller(self, outlet):
        return self.PSUs[outlet['psu_name']].feeds[outlet['feed_name']].controller

    def turn_on_outlet(self, outlet=None):
        """
            Turnning on an outlet. The outlet contains enough information
            to identify the pdu controller + outlet ID.
            when outlet is None, all outlets will be turned off.
        """
        if outlet is not None:
            return self._get_controller(outlet).turn_on_outlet(outlet['outlet_id'])
        else:
            # turn on all outlets
            ret = True
            for psu_name, psu in self.PSUs.items():
                for feed_name, feed in psu.feeds.items():
                    for outlet in feed.outlets:
                        rc = self._get_controller(outlet).turn_on_outlet(outlet['outlet_id'])
                        ret = ret and rc
        return ret

    def turn_off_outlet(self, outlet=None):
        """
            Turnning off an outlet. The outlet contains enough information
            to identify the pdu controller + outlet ID.
            when outlet is None, all outlets will be turned off.
        """
        if outlet is not None:
            return self._get_controller(outlet).turn_off_outlet(outlet['outlet_id'])
        else:
            # turn on all outlets
            ret = True
            for psu_name, psu in self.PSUs.items():
                for feed_name, feed in psu.feeds.items():
                    for outlet in feed.outlets:
                        rc = self._get_controller(outlet).turn_off_outlet(outlet['outlet_id'])
                        ret = ret and rc
        return ret

    def get_outlet_status(self, outlet=None):
        """
            Getting outlet status. The outlet contains enough information
            to identify the pdu controller + outlet ID.
            when outlet is None, status of all outlets will be returned.
        """
        status = []
        if outlet is not None:
            outlets = self._get_controller(outlet).get_outlet_status(outlet=outlet['outlet_id'])
            pdu_name = outlet['pdu_name']
            psu_name = outlet['psu_name']
            feed_name = outlet['feed_name']
            for outlet in outlets:
                outlet['pdu_name'] = pdu_name
                outlet['psu_name'] = psu_name
                outlet['feed_name'] = feed_name
            status = status + outlets
        else:
            # collect all status
            for psu_name, psu in self.PSUs.items():
                for feed_name, feed in psu.feeds.items():
                    for outlet in feed.outlets:
                        pdu_name = outlet['pdu_name']
                        outlets = feed.controller.get_outlet_status(outlet=outlet['outlet_id'])
                        for outlet in outlets:
                            outlet['pdu_name'] = pdu_name
                            outlet['psu_name'] = psu_name
                            outlet['feed_name'] = feed_name
                        status = status + outlets
        return status

    def close(self):
        for controller in Feed.controllers:
            controller.close()


def _build_pdu_manager_from_graph(pduman, dut_hostname, conn_graph_facts, pdu_vars):
    logger.info('Creating pdu manager from graph information')
    pdu_links = conn_graph_facts['device_pdu_links']
    if dut_hostname not in pdu_links or not pdu_links[dut_hostname]:
        # No PDU information in graph
        logger.info('PDU informatin for {} is not found in graph'.format(dut_hostname))
        return False

    for psu_name, psu_peer in list(pdu_links[dut_hostname].items()):
        pduman.add_controller(psu_name, psu_peer, pdu_vars[psu_name])

    return len(pduman.PSUs) > 0


def _build_pdu_manager_from_inventory(pduman, dut_hostname, pdu_hosts, pdu_vars):
    logger.info('Creating pdu manager from inventory information')
    if not pdu_hosts:
        logger.info('Do not have sufficient PDU information to create PDU manager for host {}'.format(dut_hostname))
        return False

    for ph, var_list in list(pdu_hosts.items()):
        controller_ip = var_list.get("ansible_host")
        if not controller_ip:
            logger.info('No "ansible_host" is defined in inventory file for "{}"'.format(pdu_hosts))
            logger.info('Unable to create pdu_controller for {}'.format(dut_hostname))
            continue

        controller_protocol = var_list.get("protocol")
        if not controller_protocol:
            logger.info(
                'No protocol is defined in inventory file for "{}". Try to use default "snmp"'.format(pdu_hosts))
            controller_protocol = 'snmp'

        # inventory does not support psu feed, so we assume a default N/A as feed
        psu_peer = {
            'N/A': {
                'peerdevice': ph,
                'HwSku': 'unknown',
                'Protocol': controller_protocol,
                'ManagementIp': controller_ip,
                'Type': 'Pdu',
                'peerport': 'probing',
            },
        }
        pduman.add_controller(ph, psu_peer, pdu_vars[psu_peer['Hostname']])

    return len(pduman.PSUs) > 0


def pdu_manager_factory(dut_hostname, pdu_hosts, conn_graph_facts, pdu_vars):
    """
    @summary: Factory function for creating PDU manager instance.
    @param dut_hostname: DUT host name.
    @param pdu_hosts: comma separated PDU host names.
    @param conn_graph_facts: connection graph facts.
    @param pdu_vars: pdu community strings
    """
    logger.info('Creating pdu manager object')
    pduman = PduManager(dut_hostname)
    if _build_pdu_manager_from_graph(pduman, dut_hostname, conn_graph_facts, pdu_vars):
        return pduman

    if _build_pdu_manager_from_inventory(pduman, dut_hostname, pdu_hosts, pdu_vars):
        return pduman

    return None
