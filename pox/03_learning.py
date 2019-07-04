# Copyright 2012 James McCauley
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
Instala regras de acordo com o campo in_port

"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

#Tabela de enderecos mac->porta
tabela_mac = {}

def _handle_ConnectionUp (event):

  ####################### REGRAS PRINCIPAIS #############################
  #Regra de encaminhamento para o controlador
  msgc = of.ofp_flow_mod()
  msgc.match.in_port = 3
  msgc.priority = 2
  msgc.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
  event.connection.send(msgc)

  log.info("Switch %s conectado.", dpidToStr(event.dpid))


def flood (event, dst):
  """ Floods the packet """
  msg = of.ofp_packet_out()
  log.info("Porta para %s desconhecida -- enviando para todas" % (dst,))
  msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD)) #of.OFPP_ALL
  msg.data = event.ofp
  msg.in_port = event.port
  event.connection.send(msg)

def drop (event, duration = None):
  """
  Drops this packet and optionally installs a flow to continue
  dropping similar ones for a while
  """
  if duration is not None:
    if not isinstance(duration, tuple):
      duration = (duration,duration)
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet)
    msg.idle_timeout = duration[0]
    msg.hard_timeout = duration[1]
    msg.buffer_id = event.ofp.buffer_id
    event.connection.send(msg)
  elif event.ofp.buffer_id is not None:
    msg = of.ofp_packet_out()
    msg.buffer_id = event.ofp.buffer_id
    msg.in_port = event.port
    event.connection.send(msg)

def _handle_PacketIn (event):
  packet = event.parsed
  packet_in = event.ofp
  tabela_mac[packet.src] = event.port # 1
  log.info("Aprendendo MAC: " + str(packet.src) + " esta na porta " + str(packet_in.in_port))
  if packet.dst.is_multicast:
    flood(event, packet.dst) # 3a
  else:
    if packet.dst not in tabela_mac: # 4
      flood(event, packet.dst) # 4a
    else:
      port = tabela_mac[packet.dst]
      if port == event.port: # 5
        # 5a
        log.warning("Same port for packet from %s -> %s on %s.%s.  Drop." % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
        drop(event, 10)
        return
      # 6
      try:
        tcp_found = packet.find('tcp')
        udp_found = packet.find('udp')
        arp_found = packet.find('arp')
        icmp_found = packet.find('icmp')
        if tcp_found:
          protocolo = 'TCP'
        elif udp_found:
          protocolo = 'UDP'
        elif arp_found:
          protocolo = 'ARP'
        elif icmp_found:
          protocolo = 'ICMP'
      except:
        protocolo = 'Nao identificado'
      log.info("Instalando regra protocolo:%s para porta %i -> %i" % (protocolo, event.port, port))
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet, event.port)
      msg.idle_timeout = 500
      msg.hard_timeout = 600
      msg.actions.append(of.ofp_action_output(port = port))
      msg.data = event.ofp # 6a
      event.connection.send(msg)


def launch ():
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
  log.info("Executando codigo...")