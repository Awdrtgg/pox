# Copyright 2012,2013 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Creates a spanning tree.

This component uses the discovery component to build a view of the network
topology, constructs a spanning tree, and then disables flooding on switch
ports that aren't on the tree by setting their NO_FLOOD bit.  The result
is that topologies with loops no longer turn your network into useless
hot packet soup.

The complexity of the original work was O(n^2) and due to some demand 
I(Awdrtgg) changed it to O(n). There might be (actually I'm sure there is) some 
problems, fallacies or holes.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from collections import defaultdict
from pox.openflow.discovery import Discovery
from pox.lib.util import dpidToStr
from pox.lib.recoco import Timer
import time

log = core.getLogger()

# Keep a list of previous port states so that we can skip some port mods
# If other things mess with port states, these may not be correct.  We
# could also refer to Connection.ports, but those are not guaranteed to
# be up to date.
_prev = defaultdict(lambda : defaultdict(lambda : None))
_new = defaultdict(lambda : defaultdict(lambda : None))

# If True, we set ports down when a switch connects
_noflood_by_default = False

# If True, don't allow turning off flood bits until a complete discovery
# cycle should have completed (mostly makes sense with _noflood_by_default).
_hold_down = False

switches = set()
sw_union_find = defaultdict()
connected_pair = []

def _handle_ConnectionUp (event):
  # When a switch connects, forget about previous port states
  global switches, sw_union_find, _prev, _new, connected_pair
  _prev[event.dpid].clear()
  _new[event.dpid].clear()

  if _noflood_by_default:
    con = event.connection
    for p in con.ports.itervalues():
      if p.port_no >= of.OFPP_MAX: continue
      _prev[con.dpid][p.port_no] = False
      _new[con.dpid][p.port_no] = False
      log.info("switch %i, port %i is no flood", con.dpid, p.port_no)
      pm = of.ofp_port_mod(port_no=p.port_no,
                          hw_addr=p.hw_addr,
                          config = of.OFPPC_NO_FLOOD,
                          mask = of.OFPPC_NO_FLOOD)
      con.send(pm)
    _invalidate_ports(con.dpid)

  if _hold_down:
    t = Timer(core.openflow_discovery.send_cycle_time + 1, _update_tree,
              kw={'force_dpid':event.dpid})
  
  if event.dpid not in switches:
    switches.add(event.dpid)
    sw_union_find[event.dpid] = event.dpid 
    connected_pair.append((event.dpid, event.dpid))
    log.info("switch %i added", event.dpid) 

def _handle_ConnectionDown (event):
  # When a switch connects, forget about previous port states
  global switches, sw_union_find, _prev, _new, connected_pair
  del _prev[event.dpid]
  del _new[event.dpid]

  if event.dpid in switches:
    switches.remove(event.dpid)
    del sw_union_find[event.dpid]
    connected_pair.remove((event.dpid, event.dpid))
    log.info("switch %i deleted", event.dpid)  
  

def _handle_LinkUp (link):
  global switches, sw_union_find, _prev, _new, connected_pair
  def flip (link):
    return Discovery.Link(link[2],link[3], link[0],link[1])
  (dp1,p1),(dp2,p2) = link.end

  if flip(link) in core.openflow_discovery.adjacency:
    if (dp1, dp2) in connected_pair:
      pass
    else: 
      if sw_union_find[dp1] == sw_union_find[dp2]:
        # They are connected undirectly
        pass
      else:
        # They belong to different subgrph
        log.info("connect %i & %i", dp1, dp2)
        # connect dp1 & dp2
        connected_pair.append((dp1, dp2))
        connected_pair.append((dp2, dp1)) 
        _new[dp1][p1] = True
        _new[dp2][p2] = True
        if sw_union_find[dp1] < sw_union_find[dp2]:
          for s in switches:
            if s is dp2: continue
            if sw_union_find[s] == sw_union_find[dp2]:
              sw_union_find[s] = sw_union_find[dp1]
          sw_union_find[dp2] = sw_union_find[dp1]
        else:
          for s in switches:
            if s is dp1: continue
            if sw_union_find[s] == sw_union_find[dp1]:
              sw_union_find[s] = sw_union_find[dp2]
          sw_union_find[dp1] = sw_union_find[dp2]
  else:
    _new[dp1][p1] = False
    _new[dp2][p2] = False

def _handle_LinkDown (link):
  global switches, sw_union_find, _prev, _new, connected_pair
  (dp1,p1),(dp2,p2) = link.end
  
  if (dp1, dp2) not in connected_pair:
    pass
  else:
    log.info("disconnect %i & %i", dp1, dp2)
    _new[dp1][p1] = False
    _new[dp2][p2] = False
    connected_pair.remove((dp1, dp2))
    connected_pair.remove((dp2, dp1))

    if dp1 < dp2:
      len_neibor_dp2, temp = 1, 0
      neibor_dp2 = set([dp2])
      sw_union_find[dp2] = dp2
      while len_neibor_dp2 <> temp:
        temp = len_neibor_dp2
        new_neibor = set()
        for s1 in switches:
          if s1 in neibor_dp2: continue 
          for s2 in neibor_dp2:
            if (s1, s2) in connected_pair:
              sw_union_find[s1] = dp2 
              new_neibor. add(s1)
          neibor_dp2 = neibor_dp2 | new_neibor
        len_neibor_dp2 = len(neibor_dp2)

    else:
      len_neibor_dp1, temp = 1, 0
      neibor_dp1 = set([dp1])
      sw_union_find[dp1] = dp1
      while len_neibor_dp1 <> temp:
        temp = len_neibor_dp1
        new_neibor = set()
        for s1 in switches:
          if s1 in neibor_dp1: continue 
          for s2 in neibor_dp1:
            if (s1, s2) in connected_pair:
              sw_union_find[s1] = dp1 
              new_neibor. add(s1)
          neibor_dp1 = neibor_dp1 | new_neibor
        len_neibor_dp1 = len(neibor_dp1)

    

def _handle_LinkEvent (event):
  # When links change, update spanning tree

  (dp1,p1),(dp2,p2) = event.link.end
  
  if event.added == 1:
    _handle_LinkUp(event.link)
  elif event.removed == 1:
    _handle_LinkDown(event.link)

  target_dict = set([dp1, dp2])

  _update_tree(update_sw=target_dict)


def _update_tree (update_sw, force_dpid = None):
  """
  Update spanning tree

  force_dpid specifies a switch we want to update even if we are supposed
  to be holding down changes.
  """

  global switches, sw_union_find, _prev, _new, connected_pair
  log.debug("Spanning tree updated")
  """
  log.info(sw_union_find)
  
  log.info(_prev)
  log.info(_new)
  log.info(connected_pair)
  """

  # Connections born before this time are old enough that a complete
  # discovery cycle should have completed (and, thus, all of their
  # links should have been discovered).
  enable_time = time.time() - core.openflow_discovery.send_cycle_time - 1

  # Now modify ports as needed
  try:
    change_count = 0
    for sw in update_sw:
      ports =  _new[sw]
      con = core.openflow.getConnection(sw)
      if con is None: continue # Must have disconnected
      if con.connect_time is None: continue # Not fully connected

      if _hold_down:
        if con.connect_time > enable_time:
          # Too young -- we should hold down changes.
          if force_dpid is not None and sw == force_dpid:
            # .. but we'll allow it anyway
            pass
          else:
            continue

      tree_ports = [p for p in ports.keys()]
      for p in con.ports.itervalues():
        if p.port_no < of.OFPP_MAX:
          if p.port_no in tree_ports:
            flood = _new[sw][p.port_no]
          else:
            if core.openflow_discovery.is_edge_port(sw, p.port_no):
              flood = True
            else:
              flood = False

          if _prev[sw][p.port_no] is flood:
            """  
            log.info("%i" % sw + ",%i" % p.port_no + "skip") 
            """
            continue # Skip
          change_count += 1
          _prev[sw][p.port_no] = flood
          _new[sw][p.port_no] = flood
          #print sw,p.port_no,flood
          #TODO: Check results
          """
          if flood:
            log.info("switch %i, port %i is flooding", sw, p.port_no)
          else:
            log.info("switch %i, port %i is no flood", sw, p.port_no)
          """

          pm = of.ofp_port_mod(port_no=p.port_no,
                               hw_addr=p.hw_addr,
                               config = 0 if flood else of.OFPPC_NO_FLOOD,
                               mask = of.OFPP_FLOOD)
          con.send(pm)

          _invalidate_ports(con.dpid)
    if change_count:
      log.info("%i ports changed", change_count)
  except:
    _prev.clear() 
    _new.clear() 
    log.exception("Couldn't push spanning tree")


_dirty_switches = {} # A map dpid_with_dirty_ports->Timer
_coalesce_period = 2 # Seconds to wait between features requests

def _invalidate_ports (dpid):
  """
  Registers the fact that port info for dpid may be out of date

  When the spanning tree adjusts the port flags, the port config bits
  we keep in the Connection become out of date.  We don't want to just
  set them locally because an in-flight port status message could
  overwrite them.  We also might not want to assume they get set the
  way we want them.  SO, we do send a features request, but we wait a
  moment before sending it so that we can potentially coalesce several.

  TLDR: Port information for this switch may be out of date for around
        _coalesce_period seconds.
  """
  if dpid in _dirty_switches:
    # We're already planning to check
    return
  t = Timer(_coalesce_period, _check_ports, args=(dpid,))
  _dirty_switches[dpid] = t

def _check_ports (dpid):
  """
  Sends a features request to the given dpid
  """
  _dirty_switches.pop(dpid,None)
  con = core.openflow.getConnection(dpid)
  if con is None: return
  con.send(of.ofp_barrier_request())
  con.send(of.ofp_features_request())
  log.debug("Requested switch features for %s", str(con))


def launch (no_flood = False, hold_down = False):
  global _noflood_by_default, _hold_down
  if no_flood is True:
    _noflood_by_default = True
  if hold_down is True:
    _hold_down = True

  def start_spanning_tree ():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("ConnectionDown", _handle_ConnectionDown)
    core.openflow_discovery.addListenerByName("LinkEvent", _handle_LinkEvent)
    log.debug("Spanning tree component ready")
  core.call_when_ready(start_spanning_tree, "openflow_discovery")
