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

from random import getrandbits
from ipaddress import IPv4Address,IPv4Network
import time

t = time.time() #Tempo do inicio da aplicacao

def geraIp():
	subnet = IPv4Network(u"152.77.0.0/255.255.0.0")
	bits = getrandbits(subnet.max_prefixlen - subnet.prefixlen)
	addr = IPv4Address(subnet.network_address+bits)
	addr_str = str(addr)
	return addr_str

def listaIp(ini,fim):
  ips = []
  for i in range(ini, fim):
    ip = geraIp()
    while ip in ips:
      ip = geraIp()
    ips.append(ip)
  return ips

log = core.getLogger()

def flood(event):
  ini = 1000
  fim = 3000
  lista_ip = listaIp(ini,fim)
  event.connection.send(of.ofp_barrier_request(xid=56789)) #0x88880001
  log.info("Barrier Request enviado em: "+str(time.time()-t)+" ID: 56789")
  for i in range (ini,fim):
    msg3 = of.ofp_flow_mod()
    msg3.match.in_port = 1
    msg3.match.dl_type = 0x0800
    msg3.match.nw_src = IPAddr(lista_ip[i-ini])
    msg3.table = 1
    msg3.actions.append(of.ofp_action_output(port = 2))
    event.connection.send(msg3)

  event.connection.send(of.ofp_barrier_request(xid=54321))
  log.info("Barrier Request enviado em: "+str(time.time()-t)+" ID: 54321")
  #event.connection.send(of.ofp_stats_request())
  log.info("Regras instaladas")

  #event.connection.send(of.ofp_flow_mod(match=of.ofp_match(in_port=1),command=of.OFPFC_DELETE))
  #log.info("Regras removidas")

def _handle_ConnectionUp (event):

  ####################### REGRAS PRINCIPAIS #############################

  #Instala a regra de ida (alterar os numeros das portas, se preciso)
  msg1 = of.ofp_flow_mod()
  msg1.match.in_port = 13
  msg1.priority = 10
  msg1.actions.append(of.ofp_action_output(port = 21))
  event.connection.send(msg1)


  #Instala a regra de volta (alterar os numeros das portas, se preciso)
  msg2 = of.ofp_flow_mod()
  msg2.match.in_port = 21
  msg2.priority = 10
  msg2.actions.append(of.ofp_action_output(port = 13))
  event.connection.send(msg2)

  #Regra de encaminhamento para o controlador
  msgc = of.ofp_flow_mod()
  msgc.match.in_port = 24
  msgc.priority = 2
  msgc.actions.append(of.ofp_action_output(port = of.OFPP_NORMAL))
  event.connection.send(msgc)

  #Regra de drop para miss
  msg0 = of.ofp_flow_mod()
  msg0.priority = 1
  event.connection.send(msg0)
  
  #################### REGRAS COMPLEMENTARES ###################################
  '''
  #Permite a passagem de regras ARP (ida e volta)
  msg3 = of.ofp_flow_mod()
  msg3.match.in_port = 13
  msg3.match.dl_type = 0x0806
  msg3.actions.append(of.ofp_action_output(port = 21))
  event.connection.send(msg3)

  msg3 = of.ofp_flow_mod()
  msg3.match.in_port = 21
  msg3.match.dl_type = 0x0806
  msg3.actions.append(of.ofp_action_output(port = 13))
  event.connection.send(msg3)


  #Permite a troca de pacotes SSH (se necessario)
  msg3 = of.ofp_flow_mod()
  msg3.match.in_port = 13
  msg3.match.dl_type = 0x0800
  msg3.match.nw_proto = 6  # tcp = 6 e udp = 17
  msg3.match.tp_dst = 22
  msg3.actions.append(of.ofp_action_output(port = 21))
  event.connection.send(msg3)

  msg3 = of.ofp_flow_mod()
  msg3.match.in_port = 21
  msg3.match.dl_type = 0x0800
  msg3.match.nw_proto = 6  # tcp = 6 e udp = 17
  msg3.match.tp_src = 22
  msg3.actions.append(of.ofp_action_output(port = 13))
  event.connection.send(msg3)
  '''

  log.info("Regras instaladas no switch %s.", dpidToStr(event.dpid))
  flood(event)

def _handle_BarrierIn(event):
  log.info("Barrier Reply recebido em: "+str(time.time()-t)+" ID: "+str(event.xid))

def launch ():
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("BarrierIn", _handle_BarrierIn)
  log.info("Executando codigo...")