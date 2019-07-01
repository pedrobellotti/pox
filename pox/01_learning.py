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

#Tabela de enderecos mac->porta
tabela_mac = {}

log = core.getLogger()

def _handle_ConnectionUp (event):

  ####################### REGRAS PRINCIPAIS #############################
  #Regra de encaminhamento para o controlador
  msgc = of.ofp_flow_mod()
  msgc.match.in_port = 3
  msgc.priority = 2
  msgc.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
  event.connection.send(msgc)

  log.info("Switch %s conectado.", dpidToStr(event.dpid))

def enviaPacote (event, pkt, porta_saida):
  """
  Instrui o swich a enviar o pacote que foi enviado para o controlador.
  "pkt" e o objeto ofp_packet_in que o switch enviou para o controlador
  por conta de um table-miss.
  """
  msg = of.ofp_packet_out()
  msg.data = pkt

  # Add an action to send to the specified port
  action = of.ofp_action_output(port = porta_saida)
  msg.actions.append(action)

  # Send message to switch
  event.connection.send(msg)

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

  #Verificando se a porta de destino esta na tabela
  if packet.dst in tabela_mac:
    print str(packet.dst) + " e um MAC conhecido. Enviando pacote"
    enviaPacote(event, packet_in, tabela_mac[packet.dst])
  else:
    print str(packet.dst) + " nao e um MAC conhecido, enviando pacote para todas as portas"
    enviaPacote(event, packet_in, of.OFPP_ALL)



def launch ():
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
  log.info("Executando codigo...")