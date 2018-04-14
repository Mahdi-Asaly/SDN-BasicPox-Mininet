from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os

import csv

log = core.getLogger()
policyFile = "%s/pox/pox/misc/firewall-policies.csv" % os.environ[ 'HOME' ] # We assume that file exists there.

class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        log.debug("Installing Firewall System...")
        self.BlockList = []
        with open(policyFile, 'rb') as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.BlockList.append((EthAddr(row['mac_0']), EthAddr(row['mac_1'])))
                self.BlockList.append((EthAddr(row['mac_1']), EthAddr(row['mac_0'])))

    def _handle_ConnectionUp (self, event):
        print("FireWall Rules:-")
        for (Source, Destination) in self.BlockList:
            match = of.ofp_match()
            match.dl_src = Source
            match.dl_dst = Destination
            msg = of.ofp_flow_mod()
            msg.match = match
            event.connection.send(msg)
        log.debug("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))
        log.debug("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")


def launch ():
	core.registerNew(Firewall)
