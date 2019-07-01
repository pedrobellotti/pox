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

def _handle_PacketIn (event):
  global tabela_mac
  packet = event.parsed # This is the parsed packet data.
  if not packet.parsed:
    log.warning("Pacote incompleto!")
    return
  packet_in = event.ofp # The actual ofp_packet_in message.

  #Aprendendo a porta de origem, caso ela nao esteja na tabela
  if packet.src not in tabela_mac:
    print "Aprendendo: MAC " + str(packet.src) + " esta na porta " + str(packet_in.in_port)
    tabela_mac[packet.src] = packet_in.in_port

  if packet.dst and packet.src in tabela_mac:
    #Verificando a porta de saida
    try:
      porta = tabela_mac[packet.dst]
      print str(packet.dst) + " e um MAC conhecido. Instalando regra: porta " + str(packet_in.in_port) + "->" + str(porta)
      #event.connection.send(of.ofp_flow_mod(match=of.ofp_match(in_port=packet_in.in_port,command=of.OFPFC_DELETE)))
    except:
      porta = of.OFPP_ALL
      print str(packet.dst) + " nao e um MAC conhecido, enviando pacote para o controlador"
    
    msg = of.ofp_flow_mod()
    msg.match.in_port = packet_in.in_port
    msg.priority = 10
    msg.actions.append(of.ofp_action_output(port = porta))
    event.connection.send(msg)
  else:
    return


def launch ():
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
  log.info("Executando codigo...")