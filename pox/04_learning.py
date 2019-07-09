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

#ovs-vsctl -- --id=@ft create Flow_Table flow_limit=100 overflow_policy=refuse -- set Bridge br0 flow_tables=0=@ft

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
  #msgc = of.ofp_flow_mod()
  #msgc.match.in_port = 3
  #msgc.priority = 2
  #msgc.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
  #event.connection.send(msgc)

  log.info("Switch %s conectado.", dpidToStr(event.dpid))

def _handle_PacketIn (event):
  global tabela_mac
  packet = event.parsed # This is the parsed packet data.
  if not packet.parsed:
    log.warning("Pacote incompleto!")
    return
  packet_in = event.ofp # The actual ofp_packet_in message.

  #Aprendendo a porta de origem, caso ela nao esteja na tabela
  if packet.src not in tabela_mac:
    log.info("Aprendendo: MAC " + str(packet.src) + " esta na porta " + str(packet_in.in_port))
    tabela_mac[packet.src] = packet_in.in_port

  try:
    porta = tabela_mac[packet.dst] #Porta destino
    log.info(str(packet.dst) + " e um MAC conhecido. Instalando regra: porta " + str(packet_in.in_port) + "->" + str(porta))
    msg = of.ofp_flow_mod()
    msg.match.dl_type = 0x0800
    msg.match.in_port = packet_in.in_port #Porta origem
    msg.match.dl_src = packet.src #MAC origem
    msg.match.dl_dst = packet.dst #MAC destino
    #Packet.next sobe para a proxima camada
    #Packet = camada enlace
    #Packet.next = camada rede
    #Packet.next.next = camada de transporte
    msg.match.nw_src = packet.next.srcip #IP origem
    msg.match.nw_dst = packet.next.dstip #IP destino
    msg.match.nw_proto = packet.next.protocol #Protocolo
    msg.match.tp_src = packet.next.next.srcport #Porta de origem (Protocolo)
    msg.match.tp_dst = packet.next.next.dstport #Porta de origem (Protocolo)
    msg.priority = 10
    msg.actions.append(of.ofp_action_output(port = porta)) #Porta destino
    event.connection.send(msg)
  except:
    log.info(str(packet.dst) + " nao e um MAC conhecido, enviando pacote para todos")
    porta = of.OFPP_FLOOD #Manda para todas as portas (pode usar of.OFPP_ALL tambem)

  msg = of.ofp_packet_out()
  msg.actions.append(of.ofp_action_output(port = porta))
  msg.data = packet_in
  msg.in_port = event.port
  event.connection.send(msg)

def launch ():
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
log.info("Executando codigo...")