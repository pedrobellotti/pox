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
from random import randint
from ipaddress import IPv4Address,IPv4Network
import time

t = time.time() #Tempo do inicio da aplicacao
pos = 0 #Posicao para percorrer o numRegras (barrierIn)
tempoEnv = 0
vRegras = []
vEnviado = []
vRecebido = []

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
print "Execucao Regras Enviado Recebido"

def flood(event, ini, fim):
  id = 77770
  global tempoEnv
  lista_ip = listaIp(ini,fim)
  tempoEnv = time.time()-t
  event.connection.send(of.ofp_barrier_request(xid=id)) #0x88880001
  #log.info("Barrier Request enviado em: "+str(time.time()-t)+" ID:"+str(id))
  time.sleep(1)
  for i in range (ini,fim):
    msg3 = of.ofp_flow_mod()
    msg3.match.in_port = 1
    msg3.priority = randint(1,32000)#i #fim-i
    msg3.match.dl_type = 0x0800
    msg3.match.nw_src = IPAddr(lista_ip[i-ini])
    msg3.table = 1
    msg3.actions.append(of.ofp_action_output(port = 2))
    event.connection.send(msg3)
  id += 1
  tempoEnv = time.time()-t
  event.connection.send(of.ofp_barrier_request(xid=id))
  log.info("Barrier Request enviado em: "+str(time.time()-t)+" ID:"+str(id))
  #event.connection.send(of.ofp_stats_request())
  log.info("Funcao de flood finalizada. Aguardando barrier reply ID 77771.")

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
  global tempoEnv
  tempoEnv = time.time()-t
  event.connection.send(of.ofp_barrier_request(xid=77777))
  #flood(event,1000,3000)

def _handle_BarrierIn(event):
  global tempoEnv
  global pos

  if (event.xid == 77777):
    event.connection.send(of.ofp_barrier_request(xid=77771))
    tempoEnv = time.time()-t

  temporec = time.time()-t
  if (event.xid == 77771 and pos > 0):
    vRecebido.append(temporec)
    v = len(vRecebido)-1
    print "1 "+str(vRegras[v])+' '+str(vEnviado[v])+' '+str(vRecebido[v])

  numRegras = [250,500,750,1000,1250,1500,1750,2000,2250] #max=2611
  #numRegras = [250,500,750]
  log.info("Barrier Reply recebido em: "+str(time.time()-t)+" ID:"+str(event.xid))
  if (event.xid == 77771 and pos < len(numRegras)):
    event.connection.send(of.ofp_flow_mod(match=of.ofp_match(in_port=1),command=of.OFPFC_DELETE))
    log.info("Regras port=1 removidas")
    log.info("Instalando " + str(numRegras[pos]) + " regras")
    flood(event,0,numRegras[pos])
    vRegras.append(numRegras[pos])
    vEnviado.append(tempoEnv)
    pos += 1
  elif(event.xid == 77771 and pos == len(numRegras)):
    log.info("Finalizado. Removendo regras port=1")
    event.connection.send(of.ofp_flow_mod(match=of.ofp_match(in_port=1),command=of.OFPFC_DELETE))
    #for i in range(len(vRegras)):
    #  print "1 "+str(vRegras[i])+' '+str(vEnviado[i])+' '+str(vRecebido[i+1])

def launch ():
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("BarrierIn", _handle_BarrierIn)
  log.info("Executando codigo...")