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

def _handle_ConnectionUp (event):
  if (dpidToStr(event.dpid) == '00-e0-4c-2a-33-4f'):
    nomeswitch = 'Switch UL'
  elif (dpidToStr(event.dpid) == '00-08-54-aa-cb-bc'):
    nomeswitch = 'Switch DL'
  elif (dpidToStr(event.dpid) == '00-06-4f-86-af-ff'):
    nomeswitch = 'Switch HW'
  elif (dpidToStr(event.dpid) == '00-40-a7-0c-01-75'):
    nomeswitch = 'Switch SW'
  else:
    nomeswitch = 'Switch desconhecido'

  log.info("%s conectado.", nomeswitch)
  msg1 = of.ofp_flow_mod()
  msg1.match.in_port = 2
  msg1.priority = 2
  msg1.actions.append(of.ofp_action_output(port = 1))
  msg1.hard_timeout = 10
  #msg1.flags |= of.OFPFF_SEND_FLOW_REM
  #event.connection.send(msg1)
  addRegra(event, msg1)

  #msg2 = of.ofp_flow_mod()
  #msg2.match.in_port = 3
  #msg2.priority = 2
  #msg2.actions.append(of.ofp_action_output(port = 2))
  #event.connection.send(msg2)
  #event.connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
  log.info("Regras adicionadas.")
  event.connection.send(of.ofp_flow_mod(match=of.ofp_match(in_port = 1),command=of.OFPFC_DELETE))

def _handle_FlowRemoved(event):
  log.info("Regra expirada")

#Trata as estatisticas do switch e move regras
def _handle_FlowStatsReceived (event):
  stats = flow_stats_to_list(event.stats) #Todas as regras em uma lista
  log.info("FlowStatsReceived -> %s", stats)

#Adiciona uma regra no switch
def addRegra (event, regra):
  regra.flags |= of.OFPFF_SEND_FLOW_REM
  event.connection.send(regra)
  log.info("Regra adicionada")

def getflowstats(event):
  event.connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

def launch ():
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
  core.openflow.addListenerByName("FlowRemoved", _handle_FlowRemoved)
  log.info("Executando codigo...")