#!/usr/bin/python
# Copyright 2012 William Yu
# wyu@ateneo.edu
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX. If not, see <http://www.gnu.org/licenses/>.
#

"""
This is a demonstration file created to show how to obtain flow 
and port statistics from OpenFlow 1.0-enabled switches. The flow
statistics handler contains a summary of web-only traffic.
"""

# standard includes
from pox.core import core
from pox.lib.util import dpidToStr
from pox.lib.util import dpid_to_str, str_to_dpid
import pox.openflow.libopenflow_01 as of
from pox.lib.recoco import Timer

# include as part of the betta branch
from pox.openflow.of_json import *

log = core.getLogger()
sHW = None
sSW = None
sUL = None
sDL = None

class LearningSwitch (object):
  #Inicializa o switch
  def __init__ (self, connection, nome):
    # Conexao com o switch
    self.connection = connection
    # Tabela MAC->Porta
    self.macToPort = {}
    # Listeners para packetIn
    connection.addListeners(self)
    # Nome do switch
    self.nome = nome
    # timer set to execute every five seconds
    if (self.nome == 'Switch SW'):
      Timer(5, self.getflowstats, recurring=True)
      Timer(6, self.testeMatch, recurring=False)
    if (self.nome == 'Switch SW'):
      #Instala a regra de ida (alterar os numeros das portas, se preciso)
      #'match': {'dl_type': 'IP', 'nw_dst': '10.1.0.2/32', 'dl_vlan_pcp': 0, 'dl_src': '78:2b:cb:c3:ce:1d', 'nw_proto': 17, 
      #'nw_tos': 0, 'tp_dst': 65534, 'tp_src': 7000, 'dl_dst': '90:2b:34:f2:bb:01', 'dl_vlan': 65535, 'nw_src': IPAddr('10.1.0.1'),
      #'in_port': 2}}
      msg1 = of.ofp_flow_mod()
      msg1.match.in_port = 1
      msg1.priority = 10
      msg1.actions.append(of.ofp_action_output(port = 2))
      msg1.idle_timeout = 60
      msg1.hard_timeout = 90
      msg1.match.dl_type = 0x800
      msg1.match.nw_dst = IPAddr('10.1.0.2')
      msg1.match.nw_src = IPAddr('10.1.0.1')
      msg1.match.dl_src = EthAddr("78:2b:cb:c3:ce:1d")
      msg1.match.dl_dst = EthAddr("90:2b:34:f2:bb:01")
      msg1.match.nw_proto = 17  # tcp = 6 e udp = 17
      msg1.match.nw_tos = 0
      msg1.match.tp_src = 65534
      msg1.match.tp_dst = 7000
      msg1.match.dl_vlan = 65535
      msg1.match.dl_vlan_pcp = 0
      self.connection.send(msg1)
      #Instala a regra de volta (alterar os numeros das portas, se preciso)
      msg2 = of.ofp_flow_mod()
      msg2.match.in_port = 2
      msg2.priority = 10
      msg2.actions.append(of.ofp_action_output(port = 1))
      msg2.idle_timeout = 60
      msg2.hard_timeout = 90
      msg2.match.dl_type = 0x800
      msg2.match.nw_src = IPAddr('10.1.0.2')
      msg2.match.nw_dst = IPAddr('10.1.0.1')
      msg2.match.dl_dst = EthAddr("78:2b:cb:c3:ce:1d")
      msg2.match.dl_src = EthAddr("90:2b:34:f2:bb:01")
      msg2.match.nw_proto = 17  # tcp = 6 e udp = 17
      msg2.match.nw_tos = 0
      msg2.match.tp_dst = 65534
      msg2.match.tp_src = 7000
      msg2.match.dl_vlan = 65535
      msg2.match.dl_vlan_pcp = 0
      self.connection.send(msg2)

  #Adiciona uma regra no switch
  def addRegra (self, regra):
    self.connection.send(regra)
    log.info ('%s: Regra adicionada' % (self.nome))
    #print regra

  #Remove uma regra no switch
  def delRegra (self, regra):
    self.connection.send(of.ofp_flow_mod(match=regra,command=of.OFPFC_DELETE))
    log.info ('%s: Regra removida' % (self.nome))
    #print regra

  def getflowstats(self):
    log.info("Enviando pedido de estatisticas para " + self.nome)
    self.connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

  # handler to display flow statistics received in JSON format
  # structure of event.stats is defined by ofp_flow_stats()
  def _handle_FlowStatsReceived (self, event):
    stats = flow_stats_to_list(event.stats)
    log.info("FlowStatsReceived from %s: %s", dpidToStr(event.connection.dpid), stats)
    numRegras = len(stats)
    log.info ("Numero de regras instaladas: %d", numRegras)
    '''
    i = 1
    for regra in event.stats:
      log.info("Regra %d", i)
      i += 1
      log.info("Packet count: %s", str(regra.packet_count))
      log.info("Hard timeout: %s", str(regra.hard_timeout)) 
      log.info("Byte count: %s", str(regra.byte_count)) 
      log.info("Duration (sec): %s", str(regra.duration_sec)) 
      log.info("Priority: %s", str(regra.priority))
      log.info("Idle timeout: %s", str(regra.idle_timeout)) 
      log.info("Cookie: %s", str(regra.cookie))
      log.info(" ")
      if (self.nome == 'Switch SW' and regra.duration_sec > 15):
        #Remove regra no SW
        self.delRegra (regra.match)
        #Adiciona regra no HW
        reg = of.ofp_flow_mod()
        reg.match = regra.match
        #Alterando in_port
        if (regra.match.in_port == 1):
          reg.match.in_port = 3
          reg.actions.append(of.ofp_action_output(port = 2))
        else:
          reg.match.in_port = 2
          reg.actions.append(of.ofp_action_output(port = 3))
        reg.priority = regra.priority
        reg.idle_timeout = regra.idle_timeout
        reg.hard_timeout = regra.hard_timeout
        reg.cookie = regra.cookie + 1 #Conta quantas vezes a regra foi trocada de switch
        sHW.addRegra (reg)
    '''

  def testeMatch(self):
    msg1 = of.ofp_match()
    msg1.dl_type = 0x800
    msg1.nw_proto = 17
    #msg1.nw_dst = IPAddr('10.1.0.2')
    msg1.nw_src = IPAddr('10.1.0.1')
    msg1.tp_src = 65534
    #msg1.tp_dst = 7000
    self.addRegra(of.ofp_flow_mod(match=msg1, command=of.OFPFC_MODIFY, actions=[of.ofp_action_output(port=3)]))

#Aguarda a conexao de um switch OpenFlow e cria learning switches
class l2_learning (object):
  def __init__ (self, ignore = None):
    #Listeners
    core.openflow.addListeners(self)
    # attach handsers to listners
    #core.openflow.addListenerByName("FlowStatsReceived", _handle_flowstats_received) 
    #core.openflow.addListenerByName("PortStatsReceived",_handle_portstats_received) 
    #Switches para ignorar
    self.ignore = set(ignore) if ignore else ()

  def _handle_ConnectionUp (self, event):
    if event.dpid in self.ignore:
      log.debug("Ignorando conexao de: %s" % (event.connection,))
      return
    log.debug("Conexao %s" % (event.connection,))
    #Verificando qual switch esta sendo conectado e colocando eles nas variaveis
    if (dpid_to_str(event.dpid) == '00-e0-4c-2a-33-4f'):
      global sUL
      sUL = LearningSwitch(event.connection, 'Switch UL')
      log.info ('Switch UL conectado.')
    elif (dpid_to_str(event.dpid) == '00-08-54-aa-cb-bc'):
      global sDL
      sDL = LearningSwitch(event.connection, 'Switch DL')
      log.info ('Switch DL conectado.')
    elif (dpid_to_str(event.dpid) == '00-06-4f-86-af-ff'):
      global sHW
      sHW = LearningSwitch(event.connection, 'Switch HW')
      log.info ('Switch HW conectado.')
    elif (dpid_to_str(event.dpid) == '00-40-a7-0c-01-75'):
      global sSW
      sSW = LearningSwitch(event.connection, 'Switch SW')
      log.info ('Switch SW conectado.')
    else:
      LearningSwitch(event.connection, 'Switch Desconhecido')
      log.info ('Switch nao identificado conectado.')

# main functiont to launch the module
def launch (ignore = None):
  #Inicializa o controlador
  if ignore:
    ignore = ignore.replace(',', ' ').split()
    ignore = set(str_to_dpid(dpid) for dpid in ignore)
  core.registerNew(l2_learning, ignore)
