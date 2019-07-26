# Copyright 2011-2012 James McCauley
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

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.util import str_to_bool
import time

log = core.getLogger()
sHW = None
sSW = None
sUL = None
sDL = None

class LearningSwitch (object):

  #Inicializa o switch
  def __init__ (self, connection):
    # Conexao com o switch
    self.connection = connection
    # Tabela MAC->Porta
    self.macToPort = {}
    # Listeners para packetIn
    connection.addListeners(self)

  #Adiciona uma regra no switch
  def addRegra (self, regra):
    self.connection.send(regra)
    #log.info ('Regra adicionada')

  #Packet In
  def _handle_PacketIn (self, event):
    if (dpid_to_str(event.dpid) == '00-e0-4c-2a-33-4f'):
      nomeswitch = 'Switch UL'
    elif (dpid_to_str(event.dpid) == '00-08-54-aa-cb-bc'):
      nomeswitch = 'Switch DL'
    elif (dpid_to_str(event.dpid) == '00-06-4f-86-af-ff'):
      nomeswitch = 'Switch HW'
    elif (dpid_to_str(event.dpid) == '00-40-a7-0c-01-75'):
      nomeswitch = 'Switch SW'
    else:
      nomeswitch = 'Switch desconhecido'
    packet = event.parsed #"Abre" o pacote
    self.macToPort[packet.src] = event.port #Adiciona na tabela a porta para o mac

    #Envia a mensagem para todos
    def flood (message = None):
      msg = of.ofp_packet_out()
      log.debug("%s: Floodando mensagem", dpid_to_str(event.dpid))
      if message is not None: log.debug(message)
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD)) #OFPP_ALL
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    #Se for multicast, envia para todos
    if packet.dst.is_multicast:
      flood()
    else:
      if packet.dst not in self.macToPort: #Se nao conhece a porta de destino, envia para todos
        log.info ("Porta para %s desconhecida, enviando para todos" % (packet.dst,))
        flood()
      else:
        port = self.macToPort[packet.dst] #Pega a porta de destino
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        #Informacoes do pacote e da regra
        dltype = msg.match.dl_type
        inport = msg.match.in_port
        dlsrc = msg.match.dl_src
        dldst = msg.match.dl_dst
        nwsrc = msg.match.nw_src
        nwdst = msg.match.nw_dst
        #protocolo = msg.match.nw_proto
        protosrc = msg.match.tp_src
        protodst = msg.match.tp_dst
        #msg.idle_timeout = 500
        #msg.hard_timeout = 600
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp
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
        #Informacoes de portas TCP/UDP
        if (protocolo == 'UDP' or protocolo == 'TCP'):
          log.info("%s: MAC conhecido. Instalando regra %s nas portas %i -> %i / %i -> %i" % (packet.dst, protocolo, event.port, port, protosrc, protodst))
        else:
          log.info("%s: MAC conhecido. Instalando regra %s nas portas %i -> %i" % (packet.dst, protocolo, event.port, port))
        self.connection.send(msg)
        global sUL
        msg2 = of.ofp_flow_mod()
        msg2.match = of.ofp_match.from_packet(packet, event.port)
        msg2.match.in_port = 1
        msg2.actions.append(of.ofp_action_output(port = 4))
        sUL.addRegra(msg2)

#Aguarda a conexao de um switch OpenFlow e cria learning switches
class l2_learning (object):
  def __init__ (self, ignore = None):
    #Listeners
    core.openflow.addListeners(self)
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
      sUL = LearningSwitch(event.connection)
      log.info ('Switch UL conectado.')
    elif (dpid_to_str(event.dpid) == '00-08-54-aa-cb-bc'):
      global sDL
      sDL = LearningSwitch(event.connection)
      log.info ('Switch DL conectado.')
    elif (dpid_to_str(event.dpid) == '00-06-4f-86-af-ff'):
      global sHW
      sHW = LearningSwitch(event.connection)
      log.info ('Switch HW conectado.')
    elif (dpid_to_str(event.dpid) == '00-40-af-0c-01-75'):
      global sSW
      sSW = LearningSwitch(event.connection)
      log.info ('Switch SW conectado.')
    else:
      LearningSwitch(event.connection)
      log.info ('Switch nao identificado conectado.')

def launch (ignore = None):
  #Inicializa o controlador
  if ignore:
    ignore = ignore.replace(',', ' ').split()
    ignore = set(str_to_dpid(dpid) for dpid in ignore)
  core.registerNew(l2_learning, ignore)
